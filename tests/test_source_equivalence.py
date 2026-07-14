from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from reverse_analyzer.source.equivalence import (
    DEFAULT_EQUIVALENCE_ASSESSMENT_PATH,
    assess_source_equivalence,
)
from reverse_analyzer.source_reconstruction import (
    reconstruct_source_project,
    summarize_source_reconstruction,
)


def _comparison(name: str) -> dict[str, object]:
    return {
        "status": "passed",
        "comparisons": [
            {
                "id": f"{name}:1",
                "name": name,
                "matched": True,
                "semantic_ir_entity_id": "fn:run",
                "expected": {"value": 7},
                "actual": {"value": 7},
            }
        ],
        "provenance": {"artifact": f"analysis/{name}.json"},
    }


def _matched_evidence() -> dict[str, object]:
    return {
        "semantic_ir": {
            "id": "semantic-ir:fixture",
            "entities": [
                {
                    "id": "fn:run",
                    "kind": "function",
                    "name": "run",
                    "provenance": ["semantic_ir.entities:fn:run"],
                },
                {
                    "id": "class:state",
                    "kind": "class",
                    "name": "State",
                    "provenance": ["semantic_ir.entities:class:state"],
                },
            ],
        },
        "project": {
            "name": "fixture",
            "placeholder": False,
            "provenance": ["analysis/project.json"],
            "symbols": [
                {
                    "entity_id": "fn:run",
                    "kind": "function",
                    "name": "run",
                    "placeholder": False,
                    "provenance": ["src/run.py:1"],
                },
                {
                    "entity_id": "class:state",
                    "kind": "class",
                    "name": "State",
                    "placeholder": False,
                    "provenance": ["src/run.py:4"],
                },
            ],
        },
        "body_recovery": {
            "status": "recovered",
            "placeholder_count": 0,
            "functions": [
                {
                    "entity_id": "fn:run",
                    "name": "run",
                    "status": "recovered",
                    "artifact": {"path": "analysis/decompiler/run.json"},
                }
            ],
        },
        "compilation": {
            "status": "passed",
            "validated_files": ["src/run.py"],
            "exit_code": 0,
            "provenance": {"validator": {"name": "fixture-compiler", "version": "1"}},
        },
        "runtime_differential_traces": _comparison("runtime"),
        "gui_matches": _comparison("gui"),
        "protocol_matches": _comparison("protocol"),
        "behavior_matches": _comparison("behavior"),
        "provenance": ["analysis/evidence-manifest.json"],
    }


class SourceEquivalenceAssessmentTests(unittest.TestCase):
    def test_matched_observations_never_claim_complete_behavior_equivalence(self) -> None:
        evidence = _matched_evidence()

        first = assess_source_equivalence(evidence)
        second = assess_source_equivalence(evidence)

        self.assertEqual(first["status"], "matched")
        self.assertIs(first["observed_evidence_matched"], True)
        self.assertIs(first["validated"], False)
        self.assertIs(first["validated_within_observed_scope"], True)
        self.assertIs(first["complete_behavior_equivalence_proven"], False)
        self.assertIs(first["perfect_equivalence_claimed"], False)
        self.assertEqual(first["claim_scope"], "observed_evidence_only")
        self.assertEqual(first["mismatch_count"], 0)
        self.assertTrue(
            all(item["status"] == "matched" for item in first["dimensions"].values())
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True, allow_nan=False),
            json.dumps(second, sort_keys=True, allow_nan=False),
        )

    def test_differential_mismatch_is_linked_to_semantic_ir(self) -> None:
        evidence = _matched_evidence()
        runtime = evidence["runtime_differential_traces"]
        assert isinstance(runtime, dict)
        comparison = runtime["comparisons"][0]
        comparison["matched"] = False
        comparison["actual"] = {"value": 9}
        runtime["status"] = "failed"

        result = assess_source_equivalence(evidence)

        self.assertEqual(result["status"], "mismatch")
        self.assertIs(result["observed_evidence_matched"], False)
        mismatch = next(
            item
            for item in result["mismatches"]
            if item["dimension"] == "runtime_differential_traces"
        )
        self.assertEqual(mismatch["semantic_ir_entity_ids"], ["fn:run"])
        self.assertIs(mismatch["association_resolved"], True)
        self.assertIs(mismatch["provenance_resolved"], True)

    def test_skeleton_gate_and_missing_provenance_remain_unverified(self) -> None:
        skeleton = assess_source_equivalence(_matched_evidence(), skeleton=True)
        self.assertEqual(skeleton["status"], "unverified")
        self.assertEqual(skeleton["reconstruction_form"]["status"], "skeleton")
        self.assertIs(skeleton["observed_evidence_matched"], False)

        evidence = _matched_evidence()
        runtime = evidence["runtime_differential_traces"]
        assert isinstance(runtime, dict)
        runtime["provenance"] = None
        missing_provenance = assess_source_equivalence(evidence)
        self.assertEqual(missing_provenance["status"], "unverified")
        self.assertEqual(
            missing_provenance["dimensions"]["runtime_differential_traces"]["status"],
            "unverified",
        )

    def test_aggregate_counts_without_observation_records_do_not_match(self) -> None:
        evidence = _matched_evidence()
        evidence["runtime_differential_traces"] = {
            "status": "passed",
            "summary": {"trace_count": 1, "matched_trace_count": 1},
            "provenance": {"artifact": "analysis/runtime-summary.json"},
        }

        result = assess_source_equivalence(evidence)

        self.assertEqual(result["status"], "unverified")
        self.assertEqual(
            result["dimensions"]["runtime_differential_traces"]["status"],
            "unverified",
        )

    def test_explicit_zero_summary_count_does_not_mean_missing(self) -> None:
        evidence = _matched_evidence()
        runtime = evidence["runtime_differential_traces"]
        assert isinstance(runtime, dict)
        runtime["summary"] = {"trace_count": 0, "matched_trace_count": 0}

        result = assess_source_equivalence(evidence)
        dimension = result["dimensions"]["runtime_differential_traces"]

        self.assertEqual(result["status"], "unverified")
        self.assertEqual(dimension["status"], "unverified")
        self.assertIs(dimension["summary_consistent"], False)
        self.assertEqual(dimension["reported_total_field_count"], 1)

    def test_conflicting_summary_aliases_remain_unverified(self) -> None:
        evidence = _matched_evidence()
        runtime = evidence["runtime_differential_traces"]
        assert isinstance(runtime, dict)
        runtime["summary"] = {
            "comparison_count": 1,
            "trace_count": 2,
            "matched_trace_count": 1,
        }

        result = assess_source_equivalence(evidence)
        dimension = result["dimensions"]["runtime_differential_traces"]

        self.assertEqual(result["status"], "unverified")
        self.assertEqual(dimension["status"], "unverified")
        self.assertIs(dimension["summary_consistent"], False)

    def test_conflicting_observation_match_signals_remain_unverified(self) -> None:
        evidence = _matched_evidence()
        runtime = evidence["runtime_differential_traces"]
        assert isinstance(runtime, dict)
        observation = runtime["comparisons"][0]
        observation["status"] = "failed"

        result = assess_source_equivalence(evidence)
        dimension = result["dimensions"]["runtime_differential_traces"]

        self.assertEqual(result["status"], "unverified")
        self.assertEqual(dimension["status"], "unverified")
        self.assertEqual(dimension["unverified_count"], 1)
        self.assertEqual(result["mismatch_count"], 0)

    def test_function_body_requires_recovery_specific_provenance(self) -> None:
        evidence = _matched_evidence()
        project = evidence["project"]
        body_recovery = evidence["body_recovery"]
        assert isinstance(project, dict)
        assert isinstance(body_recovery, dict)
        function_symbol = project["symbols"][0]
        function_report = body_recovery["functions"][0]
        function_symbol["provenance"] = []
        function_report.pop("artifact")

        result = assess_source_equivalence(evidence)
        dimension = result["dimensions"]["function_body_recovery"]

        self.assertEqual(dimension["status"], "mismatch")
        self.assertEqual(dimension["matched_count"], 0)
        self.assertTrue(
            any(
                item["dimension"] == "function_body_recovery"
                for item in result["mismatches"]
            )
        )

    def test_passed_compile_with_nonzero_exit_code_is_a_mismatch(self) -> None:
        evidence = _matched_evidence()
        compilation = evidence["compilation"]
        assert isinstance(compilation, dict)
        compilation["exit_code"] = 3

        result = assess_source_equivalence(evidence)
        dimension = result["dimensions"]["compile_result"]

        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(dimension["status"], "mismatch")
        self.assertEqual(dimension["exit_code"], 3)
        self.assertTrue(
            any(
                item["kind"] == "compilation_exit_code_mismatch"
                for item in result["mismatches"]
            )
        )

    def test_each_observation_can_supply_provenance_without_parent_artifact(self) -> None:
        evidence = _matched_evidence()
        for name in (
            "runtime_differential_traces",
            "gui_matches",
            "protocol_matches",
            "behavior_matches",
        ):
            comparison = evidence[name]
            assert isinstance(comparison, dict)
            comparison.pop("provenance")
            comparison["comparisons"][0]["provenance"] = [f"analysis/{name}:1"]

        result = assess_source_equivalence(evidence)

        self.assertEqual(result["status"], "matched")
        self.assertTrue(
            all(
                result["dimensions"][name]["provenance_complete"]
                for name in (
                    "runtime_differential_traces",
                    "gui_matches",
                    "protocol_matches",
                    "behavior_matches",
                )
            )
        )

    def test_summary_only_preserves_contract_valid_matched_assessment(self) -> None:
        assessment = assess_source_equivalence(_matched_evidence())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project_dir = root / "reconstructed_fixture"
            assessment_path = project_dir / "analysis" / "equivalence_assessment.json"
            assessment_path.parent.mkdir(parents=True, exist_ok=True)
            assessment_path.write_text(json.dumps(assessment), encoding="utf-8")
            source = project_dir / "src" / "run.py"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("def run():\n    return 7\n", encoding="utf-8")

            project = summarize_source_reconstruction(root)["projects"][0]
            self.assertEqual(project["equivalence_assessment_status"], "matched")
            self.assertIs(project["observed_evidence_matched"], True)

            assessment["complete_behavior_equivalence_proven"] = True
            assessment_path.write_text(json.dumps(assessment), encoding="utf-8")
            downgraded = summarize_source_reconstruction(root)["projects"][0]

            self.assertEqual(
                downgraded["equivalence_assessment_status"], "unverified"
            )
            self.assertIs(downgraded["observed_evidence_matched"], False)
            self.assertIs(
                downgraded["complete_behavior_equivalence_proven"], False
            )

    def test_reconstruction_writes_and_summarizes_assessment_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "fixture.exe"
            sample.write_bytes(b"MZ fixture")

            result = reconstruct_source_project(
                sample,
                root / "out",
                {
                    "semantic_ir": {
                        "entities": [
                            {
                                "id": "fn:restore",
                                "kind": "function",
                                "name": "restore_state",
                                "sources": ["decompiler.functions"],
                            }
                        ]
                    }
                },
                strategy="c",
            )

            project_dir = Path(result["project_dir"])
            assessment_path = project_dir.joinpath(
                *DEFAULT_EQUIVALENCE_ASSESSMENT_PATH.split("/")
            )
            self.assertTrue(assessment_path.is_file())
            self.assertEqual(
                json.loads(assessment_path.read_text(encoding="utf-8")),
                result["equivalence_assessment"],
            )
            self.assertIs(
                result["equivalence_assessment"]["complete_behavior_equivalence_proven"],
                False,
            )
            self.assertIn(str(assessment_path), result["generated_files"])
            artifact = next(
                item
                for item in result["artifacts"]
                if item.get("name") == DEFAULT_EQUIVALENCE_ASSESSMENT_PATH
            )
            self.assertEqual(artifact["role"], "evidence_assessment")
            self.assertIs(artifact["complete_behavior_equivalence_proven"], False)
            self.assertTrue(
                any(
                    item.get("name") == DEFAULT_EQUIVALENCE_ASSESSMENT_PATH
                    and item.get("role") == "evidence_assessment"
                    for item in result["evidence_manifest_entries"]
                )
            )

            summary = summarize_source_reconstruction(root)
            project = summary["projects"][0]
            self.assertEqual(
                project["equivalence_assessment_status"],
                result["equivalence_assessment"]["status"],
            )
            self.assertIs(project["complete_behavior_equivalence_proven"], False)
            self.assertEqual(summary["summary"]["equivalence_assessment_project_total"], 1)


if __name__ == "__main__":
    unittest.main()
