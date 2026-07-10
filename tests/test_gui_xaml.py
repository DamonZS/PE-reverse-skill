import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.tools.gui_xaml import extract_xaml_ui_evidence, parse_xaml_file


VALID_XAML = """<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="Sample &amp; Test">
  <Grid>
    <Button x:Name="saveButton" Content="Save" Width="90" Height="28" Margin="5" Grid.Row="1" Grid.Column="2" Click="SaveButton_Click" />
    <TextBox Name="nameBox" Text="Alice" TextChanged="NameChanged" />
    <CheckBox Content="Enabled" Checked="EnabledChanged" />
  </Grid>
</Window>"""


class GuiXamlTests(unittest.TestCase):
    def test_parses_controls_layout_and_event_handlers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "MainWindow.xaml"
            path.write_text(VALID_XAML, encoding="utf-8")

            result = parse_xaml_file(path)

            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["title"], "Sample & Test")
            self.assertEqual([node["type"] for node in result["nodes"]], ["Window", "Grid", "Button", "TextBox", "CheckBox"])
            button = next(node for node in result["nodes"] if node["id"] == "saveButton")
            self.assertEqual(button["text"], "Save")
            self.assertEqual(button["properties"]["Grid.Row"], "1")
            self.assertEqual(button["event_handlers"]["Click"], "SaveButton_Click")
            self.assertEqual(button["parent_id"], "grid_2")
            json.dumps(result)

    def test_invalid_xaml_returns_structured_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.xaml"
            path.write_text("<Window><Button></Window>", encoding="utf-8")

            result = parse_xaml_file(path)

            self.assertEqual(result["status"], "error")
            self.assertEqual(result["nodes"], [])
            self.assertEqual(result["errors"][0]["type"], "xml_parse_error")

    def test_batch_extract_is_partial_when_one_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid = root / "MainWindow.xaml"
            broken = root / "broken.xaml"
            valid.write_text(VALID_XAML, encoding="utf-8")
            broken.write_text("<Window>", encoding="utf-8")

            result = extract_xaml_ui_evidence([valid, broken])

            self.assertEqual(result["status"], "partial")
            self.assertGreater(result["node_count"], 0)
            self.assertEqual(len(result["errors"]), 1)
            self.assertEqual(result["source"], "xaml")

    def test_empty_input_is_unavailable_instead_of_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = extract_xaml_ui_evidence([], out_dir=tmp)

            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["node_count"], 0)
            self.assertTrue((Path(tmp) / "gui" / "xaml_evidence.json").is_file())


if __name__ == "__main__":
    unittest.main()
