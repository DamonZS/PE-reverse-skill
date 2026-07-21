from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from reverse_analyzer.dashboard import build_dashboard


class DashboardCampaignTests(unittest.TestCase):
    def test_detailed_campaign_artifacts_build_tree_trace_verdicts_and_trend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            engine = workspace / "llm_jailbreak" / "session-1" / "engine"
            self._write(
                engine / "campaign.json",
                {
                    "name": "comparison-a",
                    "target": {"model": "MODEL"},
                    "semantic_judge": "independent-model",
                },
            )
            self._write(
                engine / "attempts.json",
                {
                    "attempts": [
                        {
                            "attempt_id": "a1",
                            "round_index": 1,
                            "strategy": "seed",
                            "score": {"score": 0.25},
                            "response": {
                                "latency_seconds": 0.2,
                                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                            },
                            "metadata": {
                                "candidate_id": "ROOT",
                                "depth": 0,
                                "attack_mode": "builtin",
                            },
                        },
                        {
                            "attempt_id": "a2",
                            "round_index": 2,
                            "strategy": "branch",
                            "score": {"score": 0.9},
                            "success": True,
                            "response": {
                                "latency_seconds": 0.3,
                                "usage": {"total_tokens": 25},
                            },
                            "metadata": {
                                "candidate_id": "CHILD",
                                "parent_id": "ROOT",
                                "depth": 1,
                                "attack_mode": "tap",
                                "cost_usd": 0.0125,
                                "semantic_judge_verdict": {
                                    "judge_name": "judge-model",
                                    "score": 0.9,
                                    "success": True,
                                    "refused": False,
                                    "confidence": 0.8,
                                    "rationale": "canary observed",
                                },
                            },
                        },
                    ]
                },
            )
            self._write(
                engine / "result.json",
                {
                    "campaign_id": "campaign-1",
                    "status": "completed",
                    "success": True,
                    "summary": {"resumed": True},
                },
            )

            data = build_dashboard(workspace)

            analytics = data["campaign_analytics"]
            self.assertEqual(analytics["campaign_count"], 1)
            self.assertEqual(analytics["attempt_count"], 2)
            self.assertEqual(analytics["total_tokens"], 40)
            self.assertEqual(analytics["total_cost_usd"], 0.0125)
            campaign = analytics["campaigns"][0]
            self.assertEqual(campaign["attempt_tree"][1]["parent_ids"], ["ROOT"])
            self.assertTrue(campaign["strategy_trace"][1]["switched"])
            self.assertEqual(campaign["judge_verdicts"][0]["judge_name"], "judge-model")
            self.assertEqual(campaign["trend"][1]["cumulative_tokens"], 40)
            self.assertEqual(campaign["trend"][1]["cumulative_latency_ms"], 500.0)
            self.assertTrue(campaign["resumed"])
            html = (workspace / "dashboard" / "index.html").read_text(encoding="utf-8")
            self.assertIn("Model Campaign Analytics", html)
            self.assertIn("Attempt tree", html)
            self.assertNotIn("prompt", json.dumps(campaign).lower())

    def test_report_summary_is_used_when_engine_artifacts_are_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            self._write(
                workspace / "output" / "report.json",
                {
                    "llm_jailbreak_analysis": {
                        "campaign_id": "report-only",
                        "model": "MODEL",
                        "status": "completed",
                        "success": False,
                        "attempt_count": 3,
                        "score": 0.4,
                        "total_tokens": 120,
                        "total_cost_usd": 0.03,
                        "latency_ms": 900,
                        "semantic_judge": "heuristic",
                        "checkpoint": {"resumed": True},
                    }
                },
            )

            analytics = build_dashboard(workspace)["campaign_analytics"]

            self.assertEqual(analytics["campaign_count"], 1)
            campaign = analytics["campaigns"][0]
            self.assertFalse(campaign["detailed"])
            self.assertEqual(campaign["attempt_count"], 3)
            self.assertEqual(campaign["total_tokens"], 120)
            self.assertTrue(campaign["resumed"])
            self.assertEqual(campaign["attempt_tree"], [])

    @staticmethod
    def _write(path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
