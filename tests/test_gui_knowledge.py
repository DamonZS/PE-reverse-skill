import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.knowledge import KnowledgeBase


class GuiKnowledgeTests(unittest.TestCase):
    def test_gui_strategy_statistics_and_framework_recommendation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(tmp)
            kb.record_gui_strategy_result(
                "wpf",
                "manual_assisted_visual_reconstruction",
                status="failed",
                visual_similarity=0.25,
                control_match_rate=0.2,
                text_match_rate=0.2,
                sample_id="sample-a",
            )
            best = kb.record_gui_strategy_result(
                "wpf",
                "extract_baml_generate_wpf",
                status="ok",
                visual_similarity=0.95,
                control_match_rate=0.9,
                text_match_rate=0.97,
                sample_id="sample-b",
            )
            kb.record_gui_strategy_result(
                "qt",
                "extract_qrc_probe_qwidget_generate_qt",
                status="ok",
                visual_similarity=0.99,
                control_match_rate=0.99,
                text_match_rate=0.99,
                sample_id="sample-c",
            )

            stored = kb.load_gui_strategies()
            recommendation = kb.recommend_gui_strategy(framework="wpf")

            self.assertEqual(best["runs"], 1)
            self.assertEqual(best["samples"], ["sample-b"])
            self.assertEqual(stored["strategies"]["wpf:extract_baml_generate_wpf"]["avg_visual_similarity"], 0.95)
            self.assertEqual(recommendation["framework"], "wpf")
            self.assertEqual(recommendation["strategy"], "extract_baml_generate_wpf")
            self.assertGreater(recommendation["score"], 10)
            self.assertTrue((Path(tmp) / "gui_strategies.json").is_file())

    def test_gui_strategy_recommendation_has_predictable_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            recommendation = KnowledgeBase(tmp).recommend_gui_strategy(framework="electron")
            self.assertEqual(recommendation["framework"], "electron")
            self.assertEqual(recommendation["strategy"], "manual_assisted_visual_reconstruction")
            self.assertEqual(recommendation["score"], 0.0)


if __name__ == "__main__":
    unittest.main()
