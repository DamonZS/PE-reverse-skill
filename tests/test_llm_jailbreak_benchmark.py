from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.llm_jailbreak.benchmark import (
    BenchmarkConfig,
    BenchmarkPricing,
    run_benchmark,
)
from reverse_analyzer.llm_jailbreak.models import ChatResponse, SUPPORTED_ATTACK_MODES


def _campaign() -> dict:
    return {
        "id": "benchmark-fixture",
        "name": "benchmark fixture",
        "objective": "Return BENCHMARK_CANARY.",
        "max_rounds": 2,
        "seed": 17,
        "stop_on_success": True,
        "strategies": ["roleplay", "encoding"],
        "attack_modes": list(SUPPORTED_ATTACK_MODES),
        "semantic_judge": "heuristic",
        "target": {
            "base_url": "https://benchmark.invalid/v1",
            "model": "fixture-model",
            "api_key_env": "BENCHMARK_KEY",
        },
        "scoring": {"canaries": ["BENCHMARK_CANARY"], "threshold": 1.0},
    }


class _Transport:
    def __init__(self, algorithm: str, calls: list[tuple[str, str]]) -> None:
        self.algorithm = algorithm
        self.calls = calls

    def complete(self, messages, *, model, temperature, max_tokens, metadata):
        del messages, temperature, max_tokens
        self.calls.append((self.algorithm, metadata["attack_mode"]))
        return ChatResponse(
            content="BENCHMARK_CANARY",
            model=model,
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            latency_seconds=0.25,
        )


class BenchmarkTests(unittest.TestCase):
    def test_five_algorithms_use_equal_budget_and_write_metrics(self):
        calls: list[tuple[str, str]] = []
        config = BenchmarkConfig(
            repetitions=1,
            pricing=BenchmarkPricing(prompt_per_1k=0.001, completion_per_1k=0.002),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = run_benchmark(
                _campaign(),
                out_dir=root,
                config=config,
                transport_factory=lambda campaign, algorithm, repetition: _Transport(
                    algorithm, calls
                ),
            )

            self.assertEqual(set(report["summary"]), set(SUPPORTED_ATTACK_MODES))
            self.assertEqual(len(report["runs"]), 5)
            self.assertEqual(len(calls), 5)
            self.assertTrue(all(expected == actual for expected, actual in calls))
            for row in report["runs"]:
                self.assertEqual(row["attempts"], 1)
                self.assertEqual(row["tokens"], {"prompt": 10, "completion": 5, "total": 15})
                self.assertEqual(row["latency_seconds"], 0.25)
                self.assertEqual(row["cost"], 0.00002)
                self.assertEqual(row["judge_agreement"], 1.0)
                self.assertTrue(row["completed_checkpoint_recovery"])
                self.assertEqual(
                    row["completed_checkpoint_recovery_scope"],
                    "completed-checkpoint/fresh-transport",
                )
            self.assertTrue(
                all(
                    values["completed_checkpoint_recovery_rate"] == 1.0
                    for values in report["summary"].values()
                )
            )
            self.assertTrue((root / "benchmark.json").is_file())
            self.assertTrue((root / "benchmark.md").is_file())
            retained = json.loads((root / "benchmark.json").read_text(encoding="utf-8"))
            self.assertEqual(retained["fingerprint"], report["fingerprint"])

    def test_model_profile_matrix_and_fingerprint_are_repeatable(self):
        config = BenchmarkConfig(
            algorithms=("builtin",),
            models=("model-a", "model-b"),
            instruction_profiles=("ctf-sandbox",),
        )
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            factory = lambda campaign, algorithm, repetition: _Transport(algorithm, [])
            left = run_benchmark(_campaign(), out_dir=first, config=config, transport_factory=factory)
            right = run_benchmark(_campaign(), out_dir=second, config=config, transport_factory=factory)
        self.assertEqual(left["fingerprint"], right["fingerprint"])
        self.assertEqual({row["model"] for row in left["runs"]}, {"model-a", "model-b"})
        self.assertEqual({row["instruction_profile"] for row in left["runs"]}, {"ctf-sandbox"})

    def test_external_instruction_path_is_content_addressed_in_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            instruction = root / "private-host-path.md"
            instruction.write_text("fixture instruction", encoding="utf-8")
            campaign = _campaign()
            campaign["instruction_files"] = [str(instruction.resolve())]

            report = run_benchmark(
                campaign,
                out_dir=root / "benchmark",
                config=BenchmarkConfig(algorithms=("builtin",)),
                transport_factory=lambda campaign, algorithm, repetition: _Transport(
                    algorithm, []
                ),
            )

            retained = json.dumps(report, sort_keys=True)
            self.assertNotIn(str(instruction.resolve()), retained)
            self.assertRegex(
                report["campaign"]["instruction_files"][0],
                r"^external/private-host-path\.md@sha256-[0-9a-f]{16}$",
            )
            self.assertRegex(report["instruction_bundle_digest"], r"^[0-9a-f]{64}$")

    def test_invalid_config_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unique"):
            BenchmarkConfig(algorithms=("builtin", "builtin"))
        with self.assertRaisesRegex(ValueError, "unsupported"):
            BenchmarkConfig(algorithms=("unknown",))
        with self.assertRaisesRegex(ValueError, "positive"):
            BenchmarkConfig(repetitions=0)
        with self.assertRaisesRegex(ValueError, "not be negative"):
            BenchmarkPricing(prompt_per_1k=-0.1)
        with self.assertRaisesRegex(ValueError, "models must be unique"):
            BenchmarkConfig(models=("same", "same"))


if __name__ == "__main__":
    unittest.main()
