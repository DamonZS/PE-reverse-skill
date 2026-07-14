import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reverse_analyzer.tools.executor import ToolResult
from reverse_analyzer.tools.gui import gui_visual_parse, gui_visual_regression


def _write_png(path: Path, color: tuple[int, int, int]) -> None:
    from PIL import Image

    Image.new("RGB", (24, 18), color).save(path)


class GuiVisualStatusTests(unittest.TestCase):
    def test_visual_parse_reports_unavailable_without_screenshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            screenshots = root / "shots"
            screenshots.mkdir()

            result = gui_visual_parse(screenshots, root / "out")

            self.assertIsInstance(result, ToolResult)
            self.assertEqual(result.status, "unavailable")
            self.assertEqual(result.data["status"], "unavailable")
            self.assertEqual(set(result.data["components"]), {"image_decode", "segmentation", "ocr", "vlm"})
            artifact = json.loads((root / "out" / "gui" / "visual_parse.json").read_text(encoding="utf-8"))
            self.assertEqual(artifact["status"], "unavailable")

    def test_visual_parse_fails_for_an_invalid_png_without_provider_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            screenshots = root / "shots"
            screenshots.mkdir()
            (screenshots / "invalid.png").write_bytes(b"not-a-png")

            result = gui_visual_parse(screenshots, root / "out")

            self.assertIsInstance(result, dict)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["decoded_screenshot_count"], 0)
            self.assertIn(result["components"]["image_decode"]["status"], {"failed", "unavailable"})
            self.assertEqual(result["components"]["segmentation"]["status"], "unavailable")
            self.assertEqual(result["components"]["vlm"]["status"], "unavailable")
            self.assertEqual(
                json.loads((root / "out" / "gui" / "visual_parse.json").read_text(encoding="utf-8"))["status"],
                "failed",
            )
            empty_provider_result = gui_visual_parse(screenshots, vlm_provider=lambda _path: {"widgets": [{}]})
            self.assertEqual(empty_provider_result["status"], "failed")

    def test_visual_parse_is_partial_when_vlm_evidence_rescues_an_invalid_png(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            screenshots = root / "shots"
            screenshots.mkdir()
            (screenshots / "invalid.png").write_bytes(b"not-a-png")

            result = gui_visual_parse(
                screenshots,
                root / "out",
                vlm_provider=lambda _path: {"widgets": [{"type": "button", "text": "Save"}]},
            )

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["components"]["vlm"]["status"], "ok")
            self.assertEqual(result["components"]["vlm"]["evidence_count"], 1)
            self.assertEqual(result["detected_widget_count"], 1)

    @unittest.skipUnless(importlib.util.find_spec("PIL"), "Pillow is required")
    def test_visual_parse_reports_ok_and_partial_from_real_decode_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(sys.modules, {"pytesseract": None}):
            root = Path(tmp)
            valid = root / "valid"
            valid.mkdir()
            _write_png(valid / "one.png", (20, 80, 140))

            ok_result = gui_visual_parse(valid, root / "out-ok")

            self.assertEqual(ok_result["status"], "ok")
            self.assertEqual(ok_result["components"]["image_decode"]["status"], "ok")
            self.assertEqual(ok_result["components"]["segmentation"]["status"], "ok")
            self.assertEqual(ok_result["components"]["ocr"]["status"], "unavailable")
            self.assertEqual(ok_result["components"]["vlm"]["status"], "unavailable")

            mixed = root / "mixed"
            mixed.mkdir()
            _write_png(mixed / "one.png", (20, 80, 140))
            (mixed / "two.png").write_bytes(b"invalid")

            partial_result = gui_visual_parse(mixed, root / "out-partial")

            self.assertEqual(partial_result["status"], "partial")
            self.assertEqual(partial_result["components"]["image_decode"]["status"], "partial")
            self.assertEqual(partial_result["components"]["segmentation"]["status"], "partial")

    def test_visual_regression_rejects_identical_undecodable_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original"
            rebuilt = root / "rebuilt"
            original.mkdir()
            rebuilt.mkdir()
            (original / "one.png").write_bytes(b"same-invalid-image")
            (rebuilt / "one.png").write_bytes(b"same-invalid-image")

            result = gui_visual_regression(original, rebuilt, root / "out")

            self.assertIsInstance(result, dict)
            self.assertEqual(result["status"], "failed")
            self.assertIsNone(result["visual_similarity"])
            self.assertEqual(result["valid_pair_count"], 0)
            self.assertEqual(result["failed_pair_count"], 1)
            self.assertIsNone(result["pairs"][0]["visual_similarity"])
            self.assertTrue(result["pairs"][0]["hash_evidence"]["byte_identical"])
            self.assertEqual(result["pairs"][0]["hash_evidence"]["original"]["status"], "ok")

    @unittest.skipUnless(importlib.util.find_spec("PIL"), "Pillow is required")
    def test_visual_regression_is_partial_for_mixed_pairs_and_ok_for_valid_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original"
            rebuilt = root / "rebuilt"
            original.mkdir()
            rebuilt.mkdir()
            _write_png(original / "one.png", (10, 30, 90))
            _write_png(rebuilt / "one.png", (10, 30, 90))

            ok_result = gui_visual_regression(original, rebuilt, root / "out-ok")

            self.assertEqual(ok_result["status"], "ok")
            self.assertEqual(ok_result["visual_similarity"], 1.0)
            self.assertEqual(ok_result["valid_pair_count"], 1)

            (original / "two.png").write_bytes(b"invalid")
            (rebuilt / "two.png").write_bytes(b"invalid")
            partial_result = gui_visual_regression(original, rebuilt, root / "out-partial")

            self.assertEqual(partial_result["status"], "partial")
            self.assertEqual(partial_result["valid_pair_count"], 1)
            self.assertEqual(partial_result["failed_pair_count"], 1)
            self.assertEqual(partial_result["visual_similarity"], 1.0)
            self.assertIsNone(partial_result["pairs"][1]["visual_similarity"])


if __name__ == "__main__":
    unittest.main()
