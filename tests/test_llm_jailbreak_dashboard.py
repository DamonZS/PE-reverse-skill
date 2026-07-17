from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from reverse_analyzer.dashboard import build_dashboard


class LlmJailbreakDashboardTests(unittest.TestCase):
    def test_dashboard_surfaces_campaign_and_strategy_recommendation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            report_path = workspace / "sessions" / "campaign-1" / "report.json"
            knowledge_path = (
                workspace
                / ".reverse_analyzer"
                / "knowledge"
                / "llm_jailbreak_strategies.json"
            )
            self._write(
                report_path,
                {
                    "llm_jailbreak_analysis": {
                        "status": "ok",
                        "model": "gpt-5",
                        "campaign_id": "campaign-1",
                        "strategy": "roleplay",
                        "attack_modes": ["pair", "tap", "crescendo"],
                        "semantic_judge": "model",
                        "instruction_profile": "reverse-skills-llm-security",
                        "instruction_bundle_digest": "b" * 64,
                        "instruction_asset_count": 4,
                        "attempt_count": 3,
                        "success": True,
                        "score": 0.92,
                        "latency_ms": 1200.0,
                    }
                },
            )
            self._write(
                knowledge_path,
                {
                    "strategies": {
                        "roleplay": {
                            "strategy": "roleplay",
                            "last_model": "gpt-5",
                            "models": {"gpt-5": 4},
                            "runs": 4,
                            "success_rate": 0.75,
                            "avg_score": 0.88,
                            "avg_attempts": 2.5,
                            "avg_latency_ms": 1000.0,
                        }
                    }
                },
            )

            data = build_dashboard(workspace)

            view = data["analysis_views"]["llm_jailbreak"]
            recommendation = data["recommendations"]["llm_jailbreak_strategy"]
            self.assertTrue(view["available"])
            self.assertEqual(view["section"], "llm_jailbreak_analysis")
            self.assertEqual(view["status"], "ok")
            metrics = {item["label"]: item["value"] for item in view["metrics"]}
            self.assertEqual(metrics["Attack modes"], "pair, tap, crescendo")
            self.assertEqual(metrics["Semantic judge"], "model")
            self.assertEqual(
                metrics["Instruction profile"],
                "reverse-skills-llm-security",
            )
            self.assertEqual(metrics["Instruction bundle digest"], "b" * 64)
            self.assertEqual(metrics["Instruction asset count"], 4)
            self.assertEqual(recommendation["model"], "gpt-5")
            self.assertEqual(recommendation["strategy"], "roleplay")
            self.assertIn(
                "Model jailbreak strategy",
                (workspace / "dashboard" / "index.html").read_text(encoding="utf-8"),
            )

    @staticmethod
    def _write(path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
