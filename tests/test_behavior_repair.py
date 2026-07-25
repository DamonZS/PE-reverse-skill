from __future__ import annotations

import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from reverse_analyzer.source.archive_behavior import validate_archive_behavior
from reverse_analyzer.source.behavior_repair import run_behavior_repair_loop


def _passed_build() -> dict[str, object]:
    return {"status": "passed", "build_passed": True, "isolated": True, "stages": []}


def _failed_build() -> dict[str, object]:
    return {"status": "failed", "build_passed": False, "isolated": True, "stages": []}


class BehaviorRepairLoopTests(unittest.TestCase):
    def test_real_subprocess_mismatch_is_repaired_rebuilt_and_revalidated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original"
            project = root / "project"
            target = project / "targets" / "app"
            original.mkdir()
            target.mkdir(parents=True)
            (original / "program.py").write_text("print('same')\n", encoding="utf-8")
            (project / "program.py").write_text("print('wrong')\n", encoding="utf-8")
            spec = self._spec()
            initial = validate_archive_behavior(original, project, spec, isolated=True)
            contexts: list[dict[str, object]] = []

            def repair(**context: object) -> dict[str, object]:
                contexts.append(context)
                (project / "program.py").write_text("print('same')\n", encoding="utf-8")
                return {
                    "applied_changes": [{"path": "targets/app/program.py"}],
                    "usage": {"input_tokens": 8, "output_tokens": 3, "total_tokens": 11},
                }

            result = run_behavior_repair_loop(
                project,
                initial,
                spec,
                repair,
                lambda _: _passed_build(),
                lambda _: validate_archive_behavior(original, project, spec, isolated=True),
            )

            self.assertEqual(result["status"], "passed", result)
            self.assertTrue(result["passed"])
            self.assertEqual(result["iterations_completed"], 1)
            self.assertEqual(result["usage"]["total_tokens"], 11)
            self.assertEqual(contexts[0]["behavior_diff"]["comparisons"][0]["name"], "stdout")
            comparison = contexts[0]["behavior_diff"]["comparisons"][0]
            self.assertEqual(comparison["original_observation"]["text"], "same\n")
            self.assertEqual(comparison["reconstructed_observation"]["text"], "wrong\n")
            evidence = project / "docs" / "behavior-repair" / "iteration-1"
            for name in ("behavior-before.json", "model-repair.json", "build-result.json", "behavior-after.json"):
                self.assertTrue((evidence / name).is_file(), name)
            persisted = json.loads((project / "docs" / "behavior-repair-loop.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted, result)
            self.assertEqual(result["artifacts"]["final_build"], "docs/behavior-repair/iteration-1/build-result.json")
            self.assertEqual(result["artifacts"]["final_behavior"], "docs/behavior-repair/iteration-1/behavior-after.json")
            validator = result["final_behavior_result"]["provenance"]["validator"]
            self.assertTrue(validator["real_subprocess"])
            self.assertFalse(validator["runner_injected"])
            self.assertFalse(validator["shell"])

    def test_persistent_mismatch_exhausts_iteration_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            mismatch = self._mismatch()
            result = run_behavior_repair_loop(
                project,
                mismatch,
                self._spec(),
                lambda **_: {"applied_changes": [{"path": "targets/app/program.py"}]},
                lambda _: _passed_build(),
                lambda _: mismatch,
                max_iterations=2,
            )
            self.assertEqual(result["status"], "exhausted")
            self.assertEqual(result["iterations_completed"], 2)
            self.assertIn("behavior_repair_iteration_budget_exhausted", result["blocking_reasons"])

    def test_missing_spec_and_non_mismatch_failure_are_dependency_gated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            called: list[str] = []
            callbacks = (
                lambda **_: called.append("repair") or {},
                lambda _: called.append("build") or _passed_build(),
                lambda _: called.append("validate") or self._mismatch(),
            )
            missing = run_behavior_repair_loop(temporary, self._mismatch(), None, *callbacks)
            invalid = run_behavior_repair_loop(
                temporary,
                {"status": "failed", "behavior_equivalent": False, "comparisons": [], "blocking_reasons": ["runtime_failed"]},
                self._spec(),
                *callbacks,
            )
            self.assertEqual(missing["status"], "dependency-gated")
            self.assertIn("behavior_validation_spec_required", missing["blocking_reasons"])
            self.assertEqual(invalid["status"], "dependency-gated")
            self.assertIn("behavior_mismatch_evidence_required", invalid["blocking_reasons"])
            self.assertEqual(called, [])

    def test_non_real_mismatch_never_invokes_repair_or_changes_source(self) -> None:
        for provenance in (
            {"real_subprocess": False, "runner_injected": False, "shell": False},
            {"real_subprocess": True, "runner_injected": True, "shell": False},
            {"real_subprocess": True, "runner_injected": False, "shell": True},
        ):
            with self.subTest(provenance=provenance), tempfile.TemporaryDirectory() as temporary:
                project = Path(temporary)
                source = project / "targets" / "app" / "program.py"
                source.parent.mkdir(parents=True)
                source.write_text("print('unchanged')\n", encoding="utf-8")
                mismatch = self._mismatch()
                mismatch["provenance"] = {"validator": provenance}
                called: list[str] = []
                result = run_behavior_repair_loop(
                    project, mismatch, self._spec(),
                    lambda **_: called.append("repair") or {"applied_changes": []},
                    lambda _: called.append("build") or _passed_build(),
                    lambda _: called.append("validate") or self._passed_behavior(),
                )
                self.assertEqual(result["status"], "dependency-gated")
                self.assertIn("strict_real_behavior_mismatch_required", result["blocking_reasons"])
                self.assertEqual(called, [])
                self.assertEqual(source.read_text(encoding="utf-8"), "print('unchanged')\n")

    def test_non_real_revalidation_cannot_start_another_repair_iteration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repairs: list[int] = []
            non_real = self._mismatch()
            non_real["provenance"] = {"validator": {"real_subprocess": True, "runner_injected": True, "shell": False}}
            result = run_behavior_repair_loop(
                temporary, self._mismatch(), self._spec(),
                lambda **context: repairs.append(int(context["iteration"])) or {"applied_changes": [{"path": "targets/app/program.py"}]},
                lambda _: _passed_build(), lambda _: non_real, max_iterations=3,
            )
            self.assertEqual(repairs, [1])
            self.assertEqual(result["status"], "dependency-gated")
            self.assertIn("strict_real_behavior_mismatch_required", result["blocking_reasons"])

    def test_build_failure_stops_without_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = project / "targets/app/program.py"
            source.parent.mkdir(parents=True)
            source.write_text("print('baseline')\n", encoding="utf-8")
            revalidated: list[Path] = []

            def repair(**_: object) -> dict[str, object]:
                source.write_text("print('attempted')\n", encoding="utf-8")
                return {"applied_changes": [{"path": "targets/app/program.py"}]}

            result = run_behavior_repair_loop(
                project,
                self._mismatch(),
                self._spec(),
                repair,
                lambda _: _failed_build(),
                lambda root: revalidated.append(root) or self._passed_behavior(),
            )
            self.assertEqual(result["status"], "failed")
            self.assertIn("behavior_repair_build_failed", result["blocking_reasons"])
            self.assertEqual(revalidated, [])
            self.assertEqual(source.read_text(encoding="utf-8"), "print('baseline')\n")
            self.assertEqual(result["attempted_applied_change_count"], 1)
            self.assertEqual(result["applied_change_count"], 0)
            self.assertEqual(result["iterations"][0]["attempted_applied_change_count"], 1)
            self.assertEqual(result["iterations"][0]["committed_applied_change_count"], 0)
            evidence = Path(temporary) / "docs" / "behavior-repair" / "iteration-1"
            for name in ("behavior-before.json", "model-repair.json", "build-result.json", "behavior-after.json"):
                self.assertTrue((evidence / name).is_file(), name)

    def test_build_failure_diagnostics_are_retried_with_rolled_back_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = project / "targets/app/program.py"
            source.parent.mkdir(parents=True)
            source.write_text("print('baseline')\n", encoding="utf-8")
            build_log = project / "docs/build-logs/build.log"
            build_log.parent.mkdir(parents=True)
            build_log.write_text("program.py:1: missing import\n", encoding="utf-8")
            contexts: list[dict[str, object]] = []

            def repair(**context: object) -> dict[str, object]:
                contexts.append(context)
                source.write_text("print('broken')\n" if len(contexts) == 1 else "print('fixed')\n", encoding="utf-8")
                return {"applied_changes": [{"path": "targets/app/program.py"}]}

            builds = 0

            def rebuild(_: Path) -> dict[str, object]:
                nonlocal builds
                builds += 1
                if builds == 1:
                    return {"status": "failed", "build_passed": False, "isolated": True, "stages": [{"name": "build", "status": "failed", "log": "docs/build-logs/build.log"}]}
                return _passed_build()

            result = run_behavior_repair_loop(
                project, self._mismatch(), self._spec(), repair, rebuild,
                lambda _: self._passed_behavior(), max_iterations=3,
            )

            self.assertEqual(result["status"], "passed", result)
            self.assertEqual(builds, 2)
            self.assertEqual(source.read_text(encoding="utf-8"), "print('fixed')\n")
            self.assertIn("missing import", contexts[1]["behavior_diff"]["previous_repair_error"])
            self.assertEqual(result["iterations"][0]["status"], "retrying")
            self.assertEqual(result["iterations"][0]["committed_applied_change_count"], 0)

    def test_model_and_build_unavailability_are_dependency_gated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def unavailable_model(**_: object) -> dict[str, object]:
                raise RuntimeError("provider offline")

            model = run_behavior_repair_loop(
                temporary, self._mismatch(), self._spec(), unavailable_model,
                lambda _: _passed_build(), lambda _: self._passed_behavior(),
            )
            self.assertEqual(model["status"], "dependency-gated")
            self.assertIn("behavior_repair_model_unavailable", model["blocking_reasons"])

        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = project / "targets/app/program.py"
            source.parent.mkdir(parents=True)
            source.write_text("print('baseline')\n", encoding="utf-8")

            def attempted_repair(**_: object) -> dict[str, object]:
                source.write_text("print('attempted')\n", encoding="utf-8")
                return {"applied_changes": [{"path": "targets/app/program.py"}]}

            def unavailable_build(_: Path) -> dict[str, object]:
                raise RuntimeError("container offline")

            build = run_behavior_repair_loop(
                project, self._mismatch(), self._spec(), attempted_repair,
                unavailable_build, lambda _: self._passed_behavior(),
            )
            self.assertEqual(build["status"], "dependency-gated")
            self.assertIn("behavior_repair_build_unavailable", build["blocking_reasons"])
            self.assertEqual(source.read_text(encoding="utf-8"), "print('baseline')\n")

    def test_revalidation_exception_rolls_back_to_buildable_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = project / "targets/app/program.py"
            source.parent.mkdir(parents=True)
            source.write_text("print('baseline')\n", encoding="utf-8")

            def repair(**_: object) -> dict[str, object]:
                source.write_text("print('attempted')\n", encoding="utf-8")
                return {"applied_changes": [{"path": "targets/app/program.py"}]}

            def unavailable(_: Path) -> dict[str, object]:
                raise RuntimeError("validator offline")

            result = run_behavior_repair_loop(
                project, self._mismatch(), self._spec(), repair,
                lambda _: _passed_build(), unavailable,
            )
            self.assertEqual(result["status"], "dependency-gated")
            self.assertIn("behavior_revalidation_unavailable", result["blocking_reasons"])
            self.assertEqual(source.read_text(encoding="utf-8"), "print('baseline')\n")
            self.assertEqual(result["applied_change_count"], 0)
            evidence = result["iterations"][0]["evidence_refresh"]
            self.assertEqual(evidence["status"], "passed")
            graph = json.loads((project / "docs/reconstruction-graph.json").read_text(encoding="utf-8"))
            self.assertEqual(graph["fingerprint"], evidence["graph_fingerprint"])
            self.assertTrue((project / "docs/project-manifest.json").is_file())
            self.assertTrue((project / "docs/build-readiness.json").is_file())

    def test_diagnostic_and_token_budgets_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            observed: list[dict[str, object]] = []
            mismatch = self._mismatch(diagnostic="x" * 1000)

            def repair(**context: object) -> dict[str, object]:
                observed.append(context)
                return {
                    "applied_changes": [{"path": "targets/app/program.py"}],
                    "usage": {"input_tokens": 4, "output_tokens": 4, "total_tokens": 8},
                }

            result = run_behavior_repair_loop(
                temporary,
                mismatch,
                self._spec(),
                repair,
                lambda _: _passed_build(),
                lambda _: mismatch,
                max_iterations=5,
                max_diagnostic_bytes=80,
                max_token_budget=8,
            )
            self.assertEqual(result["status"], "exhausted")
            self.assertEqual(result["iterations_completed"], 1)
            self.assertLessEqual(result["diagnostic_bytes_consumed"], 80)
            self.assertTrue(observed[0]["behavior_diff"]["truncated"])
            self.assertIn("behavior_repair_token_budget_exhausted", result["blocking_reasons"])

    def test_single_response_over_token_budget_rolls_back_without_building(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = project / "targets" / "app" / "program.py"
            source.parent.mkdir(parents=True)
            source.write_text("print('before')\n", encoding="utf-8")
            built: list[Path] = []
            remaining: list[int] = []

            def repair(**context: object) -> dict[str, object]:
                remaining.append(int(context["remaining_token_budget"]))
                source.write_text("print('over-budget')\n", encoding="utf-8")
                return {
                    "applied_changes": [{"path": "targets/app/program.py"}],
                    "calls": [{"module_id": "app"}],
                    "usage": {"input_tokens": 6, "output_tokens": 5, "total_tokens": 1},
                }

            result = run_behavior_repair_loop(
                project, self._mismatch(), self._spec(), repair,
                lambda root: built.append(root) or _passed_build(),
                lambda _: self._passed_behavior(), max_token_budget=10,
            )
            self.assertEqual(remaining, [10])
            self.assertEqual(result["status"], "exhausted")
            self.assertEqual(result["call_count"], 1)
            self.assertIn("behavior_repair_token_budget_exceeded", result["blocking_reasons"])
            self.assertEqual(source.read_text(encoding="utf-8"), "print('before')\n")
            self.assertEqual(built, [])

    def test_complete_behavior_context_is_bounded_before_callback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            observed: list[tuple[int, int]] = []
            mismatch = self._mismatch(diagnostic="d" * 50_000)
            mismatch["runs"] = {
                "original": {"stdout": {"text": "o" * 50_000}},
                "reconstructed": {"stdout": {"text": "r" * 50_000}},
            }

            def repair(**context: object) -> dict[str, object]:
                encoded = json.dumps(context["behavior_diff"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                observed.append((len(encoded), int(context["diagnostic_context_bytes"])))
                return {"applied_changes": [{"path": "targets/app/program.py"}]}

            run_behavior_repair_loop(
                temporary, mismatch, self._spec(), repair,
                lambda _: _failed_build(), lambda _: mismatch,
                max_diagnostic_bytes=256,
            )
            self.assertEqual(len(observed), 1)
            self.assertLessEqual(observed[0][0], 256)
            self.assertEqual(observed[0][0], observed[0][1])

    def test_structured_invalid_model_response_has_stable_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_behavior_repair_loop(
                temporary, self._mismatch(), self._spec(),
                lambda **_: {"status": "failed", "error": "module schema invalid", "calls": [{"status": "failed"}], "applied_changes": []},
                lambda _: _passed_build(), lambda _: self._passed_behavior(),
            )
            self.assertEqual(result["status"], "dependency-gated")
            self.assertIn("behavior_repair_model_invalid", result["blocking_reasons"])
            self.assertNotIn("behavior_repair_produced_no_applied_changes", result["blocking_reasons"])

    def test_direct_malformed_callback_result_is_model_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_behavior_repair_loop(
                temporary, self._mismatch(), self._spec(),
                lambda **_: {"applied_changes": "not-a-sequence"},
                lambda _: _passed_build(), lambda _: self._passed_behavior(),
            )
            self.assertIn("behavior_repair_model_invalid", result["blocking_reasons"])
            self.assertNotIn("behavior_repair_model_unavailable", result["blocking_reasons"])

    def test_rollback_refresh_failure_preserves_original_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = project / "targets/app/program.py"
            source.parent.mkdir(parents=True)
            source.write_text("print('baseline')\n", encoding="utf-8")

            def repair(**_: object) -> dict[str, object]:
                source.write_text("print('attempted')\n", encoding="utf-8")
                return {"applied_changes": [{"path": "targets/app/program.py"}]}

            from reverse_analyzer.source import behavior_repair as behavior_repair_module
            real_refresh = behavior_repair_module._refresh_project_evidence
            refresh_calls = 0

            def fail_rollback_refresh(root: Path):
                nonlocal refresh_calls
                refresh_calls += 1
                if refresh_calls == 2:
                    raise RuntimeError("graph writer failed")
                return real_refresh(root)

            with patch("reverse_analyzer.source.behavior_repair._refresh_project_evidence", side_effect=fail_rollback_refresh):
                result = run_behavior_repair_loop(
                    project, self._mismatch(), self._spec(), repair,
                    lambda _: _failed_build(), lambda _: self._passed_behavior(),
                )
            self.assertEqual(source.read_text(encoding="utf-8"), "print('baseline')\n")
            self.assertIn("behavior_repair_build_failed", result["blocking_reasons"])
            self.assertIn("behavior_repair_evidence_refresh_failed", result["blocking_reasons"])
            evidence = result["iterations"][0]["evidence_refresh"]
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("graph writer failed", evidence["error"])
            self.assertEqual(result["iterations"][0]["status"], "dependency-gated")
            self.assertIn("graph writer failed", result["iterations"][0]["error"])

    def test_build_failure_rollback_rebuilds_matching_evidence_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            target = project / "targets/app"
            target.mkdir(parents=True)
            source = target / "program.py"
            source.write_text("print('baseline')\n", encoding="utf-8")

            def repair(**_: object) -> dict[str, object]:
                source.write_text("def attempted():\n    return 1\n", encoding="utf-8")
                return {"applied_changes": [{"path": "targets/app/program.py"}]}

            result = run_behavior_repair_loop(
                project, self._mismatch(), self._spec(), repair,
                lambda _: _failed_build(), lambda _: self._passed_behavior(),
            )
            evidence = result["iterations"][0]["evidence_refresh"]
            self.assertEqual(evidence["status"], "passed")
            graph = json.loads((project / "docs/reconstruction-graph.json").read_text(encoding="utf-8"))
            self.assertEqual(graph["fingerprint"], evidence["graph_fingerprint"])
            self.assertFalse(any(node.get("name") == "attempted" for node in graph["nodes"]))
            project_manifest = json.loads((project / "docs/project-manifest.json").read_text(encoding="utf-8"))
            source_evidence = project_manifest["targets"][0]["source_files"][0]
            self.assertEqual(source_evidence["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertTrue((project / "docs/build-readiness.json").is_file())

    def test_reconstructed_command_paths_are_exposed_as_bounded_module_hints(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            observed: list[dict[str, object]] = []
            mismatch = self._mismatch()
            mismatch["commands"] = {
                "reconstructed": {"argv": [sys.executable, "targets/app/program.py"]},
            }
            run_behavior_repair_loop(
                temporary, mismatch, self._spec(),
                lambda **context: observed.append(context["behavior_diff"]) or {"applied_changes": [{"path": "targets/app/program.py"}]},
                lambda _: _failed_build(), lambda _: mismatch,
            )
            self.assertEqual(observed[0]["target_hints"], ["targets/app/program.py"])

    @staticmethod
    def _spec() -> dict[str, object]:
        return {
            "original": {"argv": [sys.executable, "program.py"]},
            "reconstructed": {"argv": [sys.executable, "program.py"]},
        }

    @staticmethod
    def _mismatch(diagnostic: str = "behavior observation differs: stdout") -> dict[str, object]:
        return {
            "status": "failed",
            "behavior_equivalent": False,
            "diagnostics": [diagnostic],
            "blocking_reasons": ["behavior_comparison_mismatch"],
            "comparisons": [{
                "name": "stdout", "kind": "normalized_stream_sha256", "matched": False,
                "original": "original-hash", "reconstructed": "reconstructed-hash",
            }],
            "summary": {"mismatched_comparison_count": 1},
            "provenance": {"validator": {"real_subprocess": True, "runner_injected": False, "shell": False}},
        }

    @staticmethod
    def _passed_behavior() -> dict[str, object]:
        return {
            "status": "passed", "behavior_equivalent": True, "blocking_reasons": [],
            "comparisons": [],
            "provenance": {"validator": {"real_subprocess": True, "runner_injected": False, "shell": False}},
        }


if __name__ == "__main__":
    unittest.main()
