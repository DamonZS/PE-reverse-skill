from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from reverse_analyzer.archive_reconstruct import (
    _artifact_evidence,
    _repair_behavior_with_model,
    _member_name,
    _model_context,
    compose_project,
    extract_archive,
    main,
    reconstruct_archive,
    run_model_reconstruction,
)
from reverse_analyzer.knowledge.reconstruction_graph import build_reconstruction_graph
from reverse_analyzer.source.behavior_repair import run_behavior_repair_loop


class _OpenAIChatFixtureHandler(BaseHTTPRequestHandler):
    requests: list[dict] = []

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])).decode("utf-8"))
        self.__class__.requests.append({"path": self.path, "authorization": self.headers.get("Authorization"), "body": body})
        user_context = json.loads(body["messages"][1]["content"])
        module_id = user_context["context"]["reconstruction"]["targets"][0]["id"]
        source_path = next(item["path"] for item in user_context["context"]["reconstruction"]["targets"][0]["source_files"] if item["path"].endswith("fixture.c"))
        content = json.dumps({
            "modules": [{"id": module_id, "responsibility": "HTTP fixture recovered module", "interfaces": [], "missing_implementations": [], "evidence": [source_path]}],
            "dependency_edges": [],
            "source_changes": [{"path": source_path, "content": "int fixture(void) { return 42; }\n", "reason": "recover fixture behavior", "evidence": [source_path]}],
        })
        response = json.dumps({
            "model": "fixture-http-model",
            "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 21, "completion_tokens": 8, "total_tokens": 29},
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *_args) -> None:
        return


class ArchiveReconstructTests(unittest.TestCase):
    def test_legacy_gb18030_zip_name_is_recovered_from_cp437(self):
        original = "风灵月影【控制端】30.15内部版/说明.txt"
        mojibake = original.encode("gb18030").decode("cp437")
        info = zipfile.ZipInfo(mojibake)
        info.flag_bits = 0

        self.assertEqual(_member_name(info), original)

    def test_artifact_evidence_hashes_files_and_directory_trees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact"
            artifact.mkdir()
            (artifact / "b.bin").write_bytes(b"second")
            (artifact / "a.txt").write_text("first", encoding="utf-8")

            evidence = _artifact_evidence(root, "artifact")
            self.assertEqual(evidence["type"], "directory")
            self.assertEqual(evidence["file_count"], 2)
            self.assertEqual(evidence["size"], 11)
            self.assertEqual(len(evidence["sha256"]), 64)
            self.assertEqual([entry["path"] for entry in evidence["entries"]], ["a.txt", "b.bin"])

            original_digest = evidence["sha256"]
            (artifact / "a.txt").write_text("changed", encoding="utf-8")
            self.assertNotEqual(_artifact_evidence(root, "artifact")["sha256"], original_digest)

    def test_behavior_repair_rejects_model_path_escape_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            target = project / "targets" / "app"
            target.mkdir(parents=True)
            (target / "program.py").write_text("print('wrong')\n", encoding="utf-8")
            results = [{"id": "app", "source": "app.exe", "kind": "windows-executable", "status": "reconstructed", "capabilities": []}]
            graph = build_reconstruction_graph(project)

            def analyzer(context):
                source = context["targets"][0]["source_files"][0]["path"]
                return {"status": "executed", "result": {
                    "modules": [{"id": "app", "responsibility": "program", "interfaces": [], "missing_implementations": [], "evidence": [source]}],
                    "dependency_edges": [],
                    "source_changes": [{"path": "../escape.py", "content": "print('escaped')\n", "reason": "bad", "evidence": [source]}],
                }}

            response = _repair_behavior_with_model(
                project, results, graph, analyzer,
                {"comparisons": [{"name": "stdout", "kind": "stream", "matched": False}]},
                "stdout mismatch", 1,
            )

            self.assertEqual(response["applied_changes"], [])
            self.assertIn("escapes module", response["calls"][0]["error"])
            self.assertFalse((project.parent / "escape.py").exists())

    def test_behavior_repair_is_atomic_when_later_module_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            for module in ("app", "helper"):
                target = project / "targets" / module
                target.mkdir(parents=True)
                (target / "program.py").write_text(f"print('{module}-before')\n", encoding="utf-8")
            results = [
                {"id": module, "source": f"{module}.dll", "kind": "windows-library", "status": "reconstructed", "capabilities": []}
                for module in ("app", "helper")
            ]
            graph = build_reconstruction_graph(project)

            def analyzer(context):
                target = context["targets"][0]
                source = target["source_files"][0]["path"]
                change_path = source if target["id"] == "app" else "../escape.py"
                return {"status": "executed", "result": {
                    "modules": [{"id": target["id"], "responsibility": "module", "interfaces": [], "missing_implementations": [], "evidence": [source]}],
                    "dependency_edges": [],
                    "source_changes": [{"path": change_path, "content": "print('changed')\n", "reason": "repair", "evidence": [source]}],
                }, "usage": {"total_tokens": 2}}

            response = _repair_behavior_with_model(
                project, results, graph, analyzer,
                {"comparisons": [{"name": "stdout", "kind": "stream", "matched": False}]},
                "stdout mismatch", 1, remaining_token_budget=10,
            )
            self.assertEqual(response["applied_changes"], [])
            self.assertEqual((project / "targets/app/program.py").read_text(encoding="utf-8"), "print('app-before')\n")
            self.assertEqual((project / "targets/helper/program.py").read_text(encoding="utf-8"), "print('helper-before')\n")
            self.assertFalse((project.parent / "escape.py").exists())

    def test_later_behavior_repair_model_context_uses_refreshed_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            target = project / "targets" / "app"
            target.mkdir(parents=True)
            (target / "program.py").write_text("print('before')\n", encoding="utf-8")
            results = [{"id": "app", "source": "app.exe", "kind": "windows-executable", "status": "reconstructed", "capabilities": []}]
            graph = build_reconstruction_graph(project)
            observed_names: list[set[str]] = []

            def analyzer(context):
                target_context = context["targets"][0]
                observed_names.append({str(node.get("name")) for node in target_context["knowledge_graph"]["nodes"]})
                source = target_context["source_files"][0]["path"]
                return {"status": "executed", "result": {
                    "modules": [{"id": "app", "responsibility": "program", "interfaces": [], "missing_implementations": [], "evidence": [source]}],
                    "dependency_edges": [],
                    "source_changes": [{"path": source, "content": "def first_repair_marker():\n    return 'changed'\n", "reason": "repair", "evidence": [source]}],
                }, "usage": {"total_tokens": 1}}

            for iteration in (1, 2):
                _repair_behavior_with_model(
                    project, results, graph, analyzer,
                    {"comparisons": [{"name": "stdout", "kind": "stream", "matched": False}]},
                    "stdout mismatch", iteration, remaining_token_budget=10,
                )

            self.assertNotIn("first_repair_marker", observed_names[0])
            self.assertIn("first_repair_marker", observed_names[1])

    def test_behavior_repair_does_not_call_next_module_after_budget_is_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            for module in ("app", "helper"):
                target = project / "targets" / module
                target.mkdir(parents=True)
                (target / "program.py").write_text("print('before')\n", encoding="utf-8")
            results = [{"id": module, "source": f"{module}.dll", "kind": "windows-library", "status": "reconstructed", "capabilities": []} for module in ("app", "helper")]
            invoked: list[str] = []

            def analyzer(context):
                target = context["targets"][0]
                invoked.append(target["id"])
                source = target["source_files"][0]["path"]
                return {"status": "executed", "result": {
                    "modules": [{"id": target["id"], "responsibility": "module", "interfaces": [], "missing_implementations": [], "evidence": [source]}],
                    "dependency_edges": [],
                    "source_changes": [{"path": source, "content": "print('changed')\n", "reason": "repair", "evidence": [source]}],
                }, "usage": {"input_tokens": 6, "output_tokens": 4, "total_tokens": 1}}

            response = _repair_behavior_with_model(
                project, results, build_reconstruction_graph(project), analyzer,
                {"comparisons": [{"name": "stdout", "kind": "stream", "matched": False}]},
                "stdout mismatch", 1, remaining_token_budget=10,
            )
            self.assertEqual(invoked, ["app"])
            self.assertEqual(response["applied_changes"], [])
            self.assertEqual(response["usage"]["total_tokens"], 10)
            self.assertEqual((project / "targets/app/program.py").read_text(encoding="utf-8"), "print('before')\n")

    def test_behavior_repair_apply_failure_rolls_back_all_modules(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            for module in ("app", "helper"):
                target = project / "targets" / module
                target.mkdir(parents=True)
                (target / "program.py").write_text(f"print('{module}-before')\n", encoding="utf-8")
            results = [{"id": module, "source": f"{module}.dll", "kind": "windows-library", "status": "reconstructed", "capabilities": []} for module in ("app", "helper")]

            def analyzer(context):
                target = context["targets"][0]
                source = target["source_files"][0]["path"]
                return {"status": "executed", "result": {
                    "modules": [{"id": target["id"], "responsibility": "module", "interfaces": [], "missing_implementations": [], "evidence": [source]}],
                    "dependency_edges": [],
                    "source_changes": [{"path": source, "content": "print('changed')\n", "reason": "repair", "evidence": [source]}],
                }, "usage": {"total_tokens": 1}}

            calls = 0

            def flaky_apply(root, target, changes):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("disk failure")
                path = root / changes[0]["path"]
                path.write_text(changes[0]["content"], encoding="utf-8")
                return [{"module_id": target["id"], "path": changes[0]["path"]}]

            with patch("reverse_analyzer.archive_reconstruct._apply_model_source_changes", side_effect=flaky_apply):
                response = _repair_behavior_with_model(
                    project, results, build_reconstruction_graph(project), analyzer,
                    {"comparisons": [{"name": "stdout", "kind": "stream", "matched": False}]},
                    "stdout mismatch", 1, remaining_token_budget=10,
                )
            self.assertEqual(response["status"], "failed")
            self.assertIn("disk failure", response["error"])
            self.assertEqual(response["applied_changes"], [])
            self.assertEqual((project / "targets/app/program.py").read_text(encoding="utf-8"), "print('app-before')\n")
            self.assertEqual((project / "targets/helper/program.py").read_text(encoding="utf-8"), "print('helper-before')\n")

    def test_production_behavior_callback_classifies_provider_exception_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            target = project / "targets/app"
            target.mkdir(parents=True)
            (target / "program.py").write_text("print('wrong')\n", encoding="utf-8")
            results = [{"id": "app", "source": "app.exe", "kind": "windows-executable", "status": "reconstructed", "capabilities": []}]
            graph = build_reconstruction_graph(project)

            def provider_failure(_context):
                raise TimeoutError("provider timed out")

            def callback(**context):
                return _repair_behavior_with_model(
                    project, results, graph, provider_failure,
                    context["behavior_diff"], context["diagnostics"], context["iteration"],
                    remaining_token_budget=context["remaining_token_budget"],
                )

            mismatch = {
                "status": "failed", "behavior_equivalent": False,
                "comparisons": [{"name": "stdout", "kind": "stream", "matched": False}],
                "blocking_reasons": ["behavior_comparison_mismatch"],
                "provenance": {"validator": {"real_subprocess": True, "runner_injected": False, "shell": False}},
            }
            result = run_behavior_repair_loop(
                project, mismatch, {"original": {}, "reconstructed": {}}, callback,
                lambda _: {"status": "passed", "build_passed": True, "isolated": True},
                lambda _: {"status": "passed", "behavior_equivalent": True, "provenance": {"validator": {"real_subprocess": True, "runner_injected": False, "shell": False}}},
            )
            self.assertIn("behavior_repair_model_unavailable", result["blocking_reasons"])
            self.assertNotIn("behavior_repair_model_invalid", result["blocking_reasons"])

    def test_production_behavior_callback_classifies_malformed_content_as_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            target = project / "targets/app"
            target.mkdir(parents=True)
            (target / "program.py").write_text("print('wrong')\n", encoding="utf-8")
            results = [{"id": "app", "source": "app.exe", "kind": "windows-executable", "status": "reconstructed", "capabilities": []}]
            graph = build_reconstruction_graph(project)

            def callback(**context):
                return _repair_behavior_with_model(
                    project, results, graph,
                    lambda _: {"status": "executed", "content": "not-json"},
                    context["behavior_diff"], context["diagnostics"], context["iteration"],
                    remaining_token_budget=context["remaining_token_budget"],
                )

            mismatch = {
                "status": "failed", "behavior_equivalent": False,
                "comparisons": [{"name": "stdout", "kind": "stream", "matched": False}],
                "provenance": {"validator": {"real_subprocess": True, "runner_injected": False, "shell": False}},
            }
            result = run_behavior_repair_loop(
                project, mismatch, {"original": {}, "reconstructed": {}}, callback,
                lambda _: {"status": "passed", "build_passed": True, "isolated": True},
                lambda _: {},
            )
            self.assertIn("behavior_repair_model_invalid", result["blocking_reasons"])
            self.assertNotIn("behavior_repair_model_unavailable", result["blocking_reasons"])

    def test_production_behavior_callback_classifies_non_mapping_return_as_invalid(self) -> None:
        for malformed in (None, ["not", "a", "mapping"]):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as temporary:
                project = Path(temporary) / "project"
                target = project / "targets/app"
                target.mkdir(parents=True)
                (target / "program.py").write_text("print('wrong')\n", encoding="utf-8")
                results = [{"id": "app", "source": "app.exe", "kind": "windows-executable", "status": "reconstructed", "capabilities": []}]
                graph = build_reconstruction_graph(project)

                def callback(**context):
                    return _repair_behavior_with_model(
                        project, results, graph, lambda _: malformed,
                        context["behavior_diff"], context["diagnostics"], context["iteration"],
                        remaining_token_budget=context["remaining_token_budget"],
                    )

                mismatch = {
                    "status": "failed", "behavior_equivalent": False,
                    "comparisons": [{"name": "stdout", "kind": "stream", "matched": False}],
                    "provenance": {"validator": {"real_subprocess": True, "runner_injected": False, "shell": False}},
                }
                result = run_behavior_repair_loop(
                    project, mismatch, {"original": {}, "reconstructed": {}}, callback,
                    lambda _: {"status": "passed", "build_passed": True, "isolated": True}, lambda _: {},
                )
                self.assertIn("behavior_repair_model_invalid", result["blocking_reasons"])
                self.assertNotIn("behavior_repair_model_unavailable", result["blocking_reasons"])

    def test_archive_behavior_mismatch_uses_model_repair_then_real_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "behavior-repair.zip"
            behavior_spec = {
                "original": {"argv": [sys.executable, "program.py"]},
                "reconstructed": {"argv": [sys.executable, "targets/app/program.py"]},
            }
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("app.exe", b"MZ-app")
                output.writestr("program.py", "print('same')\n")
                output.writestr("behavior-validation.json", json.dumps(behavior_spec))

            def runner(command):
                analysis = Path(command[list(command).index("--out") + 1])
                project = analysis / "reconstructed_fixture"
                project.mkdir(parents=True)
                (project / "CMakeLists.txt").write_text("add_library(fixture STATIC fixture.c)\n", encoding="utf-8")
                (project / "project.json").write_text("{}", encoding="utf-8")
                (project / "fixture.c").write_text("int fixture(void) { return 1; }\n", encoding="utf-8")
                (project / "program.py").write_text("print('wrong')\n", encoding="utf-8")
                return 0

            phases: list[str] = []

            def analyzer(context):
                target = context["targets"][0]
                phase = "behavior-repair" if "behavior_repair" in context else "reconstruction"
                phases.append(phase)
                source = next(item["path"] for item in target["source_files"] if item["path"].endswith("program.py"))
                content = (
                    "def repaired_marker():\n    return 'same'\n\nprint(repaired_marker())\n"
                    if phase == "behavior-repair"
                    else "print('wrong')\n"
                )
                return {
                    "status": "executed", "provider": "fixture", "model": "fixture-model",
                    "result": {
                        "modules": [{"id": target["id"], "responsibility": "program", "interfaces": [], "missing_implementations": [], "evidence": [source]}],
                        "dependency_edges": [],
                        "source_changes": [{"path": source, "content": content, "reason": phase, "evidence": [source]}],
                    },
                    "usage": {"input_tokens": 5, "output_tokens": 2, "total_tokens": 7},
                }

            passed_build = {
                "status": "passed", "build_passed": True, "isolated": True,
                "isolation": {"kind": "container"}, "artifact_count": 1,
                "blocking_reasons": [], "stages": [{"name": "configure", "status": "passed"}, {"name": "build", "status": "passed"}],
            }
            environment = {
                "REVERSE_ANALYZER_BEHAVIOR_SANDBOX": "1",
                "REVERSE_ANALYZER_BEHAVIOR_REPAIR_ITERATIONS": "2",
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                patch("reverse_analyzer.source.project_builder.build_project", return_value=passed_build),
            ):
                manifest = reconstruct_archive(archive, root / "analysis", runner=runner, model_analyzer=analyzer)

            self.assertEqual(phases, ["reconstruction", "behavior-repair"])
            self.assertEqual(manifest["behavior_validation"]["status"], "passed")
            self.assertTrue(manifest["behavior_validation"]["behavior_equivalent"])
            self.assertEqual(manifest["behavior_repair"]["status"], "passed")
            self.assertEqual(manifest["behavior_repair"]["iterations_completed"], 1)
            project = Path(manifest["project_dir"])
            repair_loop = json.loads((project / "docs/behavior-repair-loop.json").read_text(encoding="utf-8"))
            model_artifact = json.loads((project / "docs/model-reconstruction.json").read_text(encoding="utf-8"))
            self.assertEqual(model_artifact["behavior_repair"]["status"], "passed")
            self.assertEqual(model_artifact["usage"]["total_tokens"], 14)
            for field in ("call_count", "usage", "attempted_applied_change_count", "applied_change_count"):
                self.assertEqual(manifest["behavior_repair"][field], repair_loop[field])
                self.assertEqual(model_artifact["behavior_repair"][field], repair_loop[field])
            self.assertEqual(repair_loop["call_count"], 1)
            graph_artifact = json.loads((project / "docs/reconstruction-graph.json").read_text(encoding="utf-8"))
            rebuilt_graph = build_reconstruction_graph(project).to_dict()
            self.assertEqual(graph_artifact["fingerprint"], rebuilt_graph["fingerprint"])
            self.assertEqual(graph_artifact["node_count"], rebuilt_graph["node_count"])
            self.assertEqual(graph_artifact["edge_count"], rebuilt_graph["edge_count"])
            self.assertTrue(any(node.get("name") == "repaired_marker" for node in graph_artifact["nodes"]))
            self.assertEqual(manifest["knowledge_graph"]["fingerprint"], graph_artifact["fingerprint"])
            self.assertEqual(manifest["knowledge_graph"]["node_count"], graph_artifact["node_count"])

    def test_cli_forwards_behavior_spec(self) -> None:
        with patch("reverse_analyzer.archive_reconstruct.reconstruct_archive") as reconstruct:
            exit_code = main(["fixture.zip", "--out", "analysis", "--behavior-spec", "validation/check.json"])

        self.assertEqual(exit_code, 0)
        reconstruct.assert_called_once_with(
            Path("fixture.zip"),
            Path("analysis"),
            behavior_spec="validation/check.json",
        )

    def test_archive_behavior_auto_spec_runs_real_python_subprocesses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "behavior.zip"
            behavior_spec = {
                "original": {"argv": [sys.executable, "program.py"]},
                "reconstructed": {"argv": [sys.executable, "targets/app/program.py"]},
            }
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("app.exe", b"MZ-app")
                output.writestr("program.py", "print('same behavior')\n")
                output.writestr("behavior-validation.json", json.dumps(behavior_spec))

            def runner(command):
                analysis = Path(command[list(command).index("--out") + 1])
                project = analysis / "reconstructed_fixture"
                project.mkdir(parents=True)
                (project / "CMakeLists.txt").write_text("add_library(fixture STATIC fixture.c)\n", encoding="utf-8")
                (project / "project.json").write_text("{}", encoding="utf-8")
                (project / "fixture.c").write_text("int fixture(void) { return 1; }\n", encoding="utf-8")
                (project / "program.py").write_text("print('same behavior')\n", encoding="utf-8")
                return 0

            with patch.dict(os.environ, {"REVERSE_ANALYZER_BEHAVIOR_SANDBOX": "1"}, clear=False):
                manifest = reconstruct_archive(archive, root / "analysis", runner=runner)

            behavior = manifest["behavior_validation"]
            self.assertEqual(behavior["status"], "passed")
            self.assertIs(behavior["behavior_equivalent"], True)
            self.assertEqual(behavior["comparison_count"], 3)
            self.assertEqual(behavior["mismatch_count"], 0)
            artifact = Path(manifest["project_dir"]) / behavior["artifact"]
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertIs(payload["provenance"]["validator"]["real_subprocess"], True)
            self.assertEqual(payload["archive_validation"]["spec_source"]["path"], "behavior-validation.json")

    def test_archive_behavior_without_spec_is_dependency_gated_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "no-behavior-spec.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("readme.txt", "fixture")

            manifest = reconstruct_archive(archive, root / "analysis", runner=lambda _command: 0)

            behavior = manifest["behavior_validation"]
            self.assertEqual(behavior["status"], "dependency-gated")
            self.assertIs(behavior["behavior_equivalent"], False)
            self.assertIn("behavior_validation_spec_required", behavior["blocking_reasons"])
            artifact = Path(manifest["project_dir"]) / behavior["artifact"]
            self.assertTrue(artifact.is_file())

    def test_reusing_out_dir_does_not_reuse_previous_behavior_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out_dir = root / "analysis"
            first = root / "first.zip"
            second = root / "second.zip"
            spec = {
                "original": {"argv": [sys.executable, "program.py"]},
                "reconstructed": {"argv": [sys.executable, "package/program.py"]},
            }
            with zipfile.ZipFile(first, "w") as output:
                output.writestr("program.py", "print('first')\n")
                output.writestr("behavior-validation.json", json.dumps(spec))
            with zipfile.ZipFile(second, "w") as output:
                output.writestr("readme.txt", "second archive")

            with patch.dict(os.environ, {"REVERSE_ANALYZER_BEHAVIOR_SANDBOX": "1"}, clear=False):
                first_manifest = reconstruct_archive(first, out_dir, runner=lambda _command: 0)
                second_manifest = reconstruct_archive(second, out_dir, runner=lambda _command: 0)

            self.assertEqual(first_manifest["behavior_validation"]["status"], "passed")
            self.assertEqual(second_manifest["behavior_validation"]["status"], "dependency-gated")
            self.assertIn(
                "behavior_validation_spec_required",
                second_manifest["behavior_validation"]["blocking_reasons"],
            )
            self.assertFalse((out_dir / "archive-workspace-v3/package/behavior-validation.json").exists())

    def test_model_token_budget_stops_later_modules(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            for module_id in ("app", "helper"):
                target = project / "targets" / module_id
                target.mkdir(parents=True)
                (target / "fixture.c").write_text("int fixture(void) { return 1; }\n", encoding="utf-8")
            results = [
                {"id": module_id, "source": f"{module_id}.dll", "kind": "windows-library", "status": "reconstructed", "capabilities": []}
                for module_id in ("app", "helper")
            ]
            invoked: list[str] = []

            def analyzer(context):
                target = context["targets"][0]
                invoked.append(target["id"])
                source = target["source_files"][0]["path"]
                return {"provider": "fixture", "result": {
                    "modules": [{"id": target["id"], "responsibility": "module", "interfaces": [], "missing_implementations": [], "evidence": [source]}],
                    "dependency_edges": [],
                    "source_changes": [{"path": source, "content": "int fixture(void) { return 2; }\n", "reason": "recover", "evidence": [source]}],
                }, "usage": {"total_tokens": 10}}

            with patch.dict(os.environ, {"REVERSE_ANALYZER_MODEL_TOKEN_BUDGET": "1"}, clear=False):
                stage = run_model_reconstruction(project, results, model_analyzer=analyzer)
            self.assertEqual(invoked, ["app"])
            self.assertEqual(stage["status"], "failed")
            payload = json.loads((project / stage["artifact"]).read_text(encoding="utf-8"))
            self.assertIn("token budget exhausted", payload["calls"][1]["error"])

    def test_model_stage_is_partial_when_only_some_modules_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            for module_id in ("app", "helper"):
                target = project / "targets" / module_id
                target.mkdir(parents=True)
                (target / "fixture.c").write_text("int fixture(void) { return 1; }\n", encoding="utf-8")
            results = [
                {"id": module_id, "source": f"{module_id}.dll", "kind": "windows-library", "status": "reconstructed", "capabilities": []}
                for module_id in ("app", "helper")
            ]

            def analyzer(context):
                target = context["targets"][0]
                source = target["source_files"][0]["path"]
                if target["id"] == "helper":
                    return {"status": "dependency-gated", "provider": "fixture", "result": {"modules": [], "dependency_edges": [], "source_changes": []}}
                return {"status": "executed", "provider": "fixture", "result": {
                    "modules": [{"id": "app", "responsibility": "module", "interfaces": [], "missing_implementations": [], "evidence": [source]}],
                    "dependency_edges": [],
                    "source_changes": [{"path": source, "content": "int fixture(void) { return 2; }\n", "reason": "recover", "evidence": [source]}],
                }}

            stage = run_model_reconstruction(project, results, model_analyzer=analyzer)
            self.assertEqual(stage["status"], "partial")
            payload = json.loads((project / stage["artifact"]).read_text(encoding="utf-8"))
            self.assertEqual([call["status"] for call in payload["calls"]], ["executed", "dependency-gated"])

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "unsafe.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("../escape.exe", b"MZ")
            with self.assertRaisesRegex(ValueError, "unsafe archive member"):
                extract_archive(archive, root / "out")
            self.assertFalse((root / "escape.exe").exists())

    def test_composite_creates_model_source_for_native_target_without_project(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "native.zip"
            archive.write_bytes(b"fixture")
            workspace = root / "workspace"
            (workspace / "package").mkdir(parents=True)
            project = compose_project(
                archive,
                root / "analysis",
                workspace,
                [],
                [{
                    "id": "winmm",
                    "source": "winmm.dll",
                    "kind": "windows-library",
                    "status": "partial",
                    "analysis_dir": "analysis-winmm",
                    "capabilities": [],
                }],
            )

            source = project / "targets" / "winmm" / "source" / "main.c"
            self.assertTrue(source.is_file())
            self.assertTrue((project / "targets" / "winmm" / "CMakeLists.txt").is_file())
            self.assertIn('add_subdirectory("targets/winmm")', (project / "CMakeLists.txt").read_text(encoding="utf-8"))
            context = _model_context(project, [{"id": "winmm", "source": "winmm.dll", "kind": "windows-library", "status": "partial", "capabilities": []}])
            paths = [item["path"] for item in context["targets"][0]["source_files"]]
            self.assertIn("targets/winmm/source/main.c", paths)

    def test_builds_composite_tree_and_routes_each_binary_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "bundle.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("app/client.exe", b"MZ-client")
                output.writestr("app/helper.dll", b"MZ-helper")
                apk = root / "fixture.apk"
                with zipfile.ZipFile(apk, "w") as apk_output:
                    apk_output.writestr("assets/apps/demo/www/index.html", "<html>demo</html>")
                    apk_output.writestr("classes.dex", b"dex\n035")
                output.writestr("mobile/client.apk", apk.read_bytes())
                output.writestr("assets/theme.json", b"{}")

            commands: list[list[str]] = []

            def runner(command):
                command = list(command)
                commands.append(command)
                analysis = Path(command[command.index("--out") + 1])
                analyzed = next((Path(value) for value in reversed(command) if str(value).endswith((".exe", ".dll", ".apk"))), None)
                if analyzed and analyzed.suffix != ".apk":
                    project = analysis / "reconstructed_fixture"
                    project.mkdir(parents=True)
                    (project / "CMakeLists.txt").write_text("add_library(fixture STATIC fixture.c)\n", encoding="utf-8")
                    (project / "project.json").write_text(json.dumps({"placeholder": False}), encoding="utf-8")
                    (project / "fixture.c").write_text("int fixture;\n", encoding="utf-8")
                    if analyzed.suffix == ".exe":
                        gui = analysis / "reconstructed_gui"
                        (gui / "src").mkdir(parents=True)
                        (gui / "src/main.py").write_text("print('gui')\n", encoding="utf-8")
                elif command[3:5] == ["android", "decompile"]:
                    jadx_source = analysis / "android/source/sources/demo"
                    jadx_source.mkdir(parents=True)
                    (jadx_source / "MainActivity.java").write_text("class MainActivity {}\n", encoding="utf-8")
                elif command[3:5] == ["android", "unpack"]:
                    destination = Path(command[command.index("--destination") + 1])
                    destination.mkdir(parents=True)
                    (destination / "AndroidManifest.xml").write_text("<manifest />\n", encoding="utf-8")
                return 0

            manifest = reconstruct_archive(archive, root / "analysis", runner=runner)
            project = Path(manifest["project_dir"])
            self.assertEqual(manifest["target_count"], 3)
            self.assertEqual(len(commands), 5)
            native = [command for command in commands if Path(command[-1]).suffix in {".exe", ".dll"} or any(
                Path(value).suffix in {".exe", ".dll"} for value in command[3:]
            )]
            self.assertTrue(all("--decompile" in command for command in native))
            exe = next(command for command in native if any(str(value).endswith("client.exe") for value in command))
            dll = next(command for command in native if any(str(value).endswith("helper.dll") for value in command))
            self.assertIn("--gui", exe)
            self.assertIn("--reconstruct-gui", exe)
            self.assertNotIn("--gui", dll)
            self.assertTrue(any(command[3:5] == ["android", "decompile"] for command in commands))
            self.assertTrue(any(command[3:5] == ["android", "unpack"] for command in commands))
            self.assertTrue((project / "package/app/client.exe").is_file())
            self.assertTrue((project / "package/assets/theme.json").is_file())
            self.assertTrue((project / "targets/client/CMakeLists.txt").is_file())
            self.assertTrue((project / "targets/client/gui/src/main.py").is_file())
            self.assertTrue((project / "targets/client_3/package/assets/apps/demo/www/index.html").is_file())
            self.assertTrue((project / "targets/client_3/source/java-kotlin/sources/demo/MainActivity.java").is_file())
            self.assertTrue((project / "targets/client_3/source/apktool/AndroidManifest.xml").is_file())
            self.assertTrue((project / "targets/client_3/capability-plan.json").is_file())
            capability_plan = json.loads((project / "targets/client_3/capability-plan.json").read_text(encoding="utf-8"))
            self.assertEqual(len(capability_plan["target_evidence"]["sha256"]), 64)
            unpack_stage = next(stage for stage in capability_plan["stages"] if stage["capability"] == "android-resource-smali-unpack")
            self.assertEqual(unpack_stage["artifact_verification"]["status"], "verified")
            self.assertEqual(unpack_stage["artifact_evidence"][0]["type"], "directory")
            self.assertEqual(len(unpack_stage["artifact_evidence"][0]["sha256"]), 64)
            self.assertTrue((project / "docs/package-inventory.json").is_file())
            self.assertTrue((project / "docs/reconstruction-graph.json").is_file())
            self.assertTrue((project / "docs/project-manifest.json").is_file())
            self.assertTrue((project / "docs/dependencies.lock.json").is_file())
            self.assertTrue((project / "docs/build-readiness.json").is_file())
            self.assertGreater(manifest["knowledge_graph"]["node_count"], 0)
            self.assertFalse(manifest["project_readiness"]["structure_complete"])
            self.assertIn("add_subdirectory", (project / "CMakeLists.txt").read_text(encoding="utf-8"))
            plans = list((root / "analysis/archive-workspace-v3/target-analysis").glob("*/capability-plan.json"))
            self.assertEqual(len(plans), 3)

    def test_dependency_stage_keeps_provider_failure_as_dependency_gated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "android.zip"
            apk = root / "client.apk"
            with zipfile.ZipFile(apk, "w") as output:
                output.writestr("classes.dex", b"dex\n035")
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("client.apk", apk.read_bytes())

            def runner(command):
                return 2 if command[3:5] == ["android", "unpack"] else 3 if command[3:5] == ["android", "decompile"] else 0

            manifest = reconstruct_archive(archive, root / "analysis", runner=runner)
            stages = manifest["targets"][0]["capabilities"]
            self.assertEqual([stage["status"] for stage in stages], ["completed", "dependency-gated", "dependency-gated"])
            self.assertTrue((Path(manifest["project_dir"]) / "targets/client/package/classes.dex").is_file())

    def test_model_provider_runs_on_real_composite_module_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "native.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("app.exe", b"MZ-app")
                output.writestr("helper.dll", b"MZ-helper")

            def runner(command):
                command = list(command)
                analysis = Path(command[command.index("--out") + 1])
                project = analysis / "reconstructed_fixture"
                project.mkdir(parents=True)
                (project / "CMakeLists.txt").write_text("add_library(fixture STATIC fixture.c)\n", encoding="utf-8")
                (project / "project.json").write_text(json.dumps({"placeholder": False}), encoding="utf-8")
                (project / "fixture.c").write_text("int fixture(void) { return 1; }\n", encoding="utf-8")
                return 0

            captured: list[dict] = []
            build_commands: list[list[str]] = []
            build_attempts = 0

            def model_analyzer(context):
                captured.append(context)
                target = context["targets"][0]
                source_path = next(item["path"] for item in target["source_files"] if item["path"].endswith("fixture.c"))
                repaired = "build_repair" in context
                graph_evidence = next((node["id"] for node in target.get("knowledge_graph", {}).get("nodes", []) if node["type"] == "ToolStage"), None)
                evidence = [source_path, graph_evidence] if graph_evidence else [source_path]
                return {
                    "provider": "fixture_llm",
                    "model": "fixture-model",
                    "content": json.dumps({
                        "modules": [{"id": target["id"], "responsibility": "recovered module", "interfaces": [], "missing_implementations": [], "evidence": [source_path]}],
                        "dependency_edges": [],
                        "source_changes": [{"path": source_path, "content": f"int fixture(void) {{ return {9 if repaired else 2 if target['id']=='app' else 3}; }}\n", "reason": "repair compiler error" if repaired else "complete recovered body", "evidence": evidence}],
                    }),
                    "usage": {"input_tokens": 120, "output_tokens": 40},
                }

            def build_runner(command, **_options):
                nonlocal build_attempts
                build_commands.append(list(command))
                if "--build" in command:
                    build_attempts += 1
                    if build_attempts == 1:
                        return subprocess.CompletedProcess(command, 2, "", "targets/app/fixture.c:1: error: expected repair")
                    output = root / "analysis" / "reconstructed_archive_native" / ".reconstruction-build" / "fixture.bin"
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(b"built")
                return subprocess.CompletedProcess(command, 0, "ok", "")

            manifest = reconstruct_archive(archive, root / "analysis", runner=runner, model_analyzer=model_analyzer, build_runner=build_runner)
            self.assertEqual(len(captured), 3)
            self.assertEqual({context["targets"][0]["id"] for context in captured}, {"app", "helper"})
            self.assertTrue(all(len(context["targets"]) == 1 for context in captured))
            self.assertTrue(all(context["targets"][0]["knowledge_graph"]["nodes"] for context in captured))
            self.assertTrue(all(any(node["type"] == "ToolStage" for node in context["targets"][0]["knowledge_graph"]["nodes"]) for context in captured[:2]))
            model_stage = manifest["model_reconstruction"]
            self.assertEqual(model_stage["status"], "executed")
            self.assertEqual(model_stage["provider"], "fixture_llm")
            artifact = Path(manifest["project_dir"]) / model_stage["artifact"]
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["result"]["modules"]), 2)
            self.assertEqual(payload["usage"]["input_tokens"], 360)
            self.assertEqual(payload["usage"]["output_tokens"], 120)
            self.assertEqual(len(payload["calls"]), 3)
            self.assertEqual(payload["applied_change_count"], 3)
            self.assertTrue((Path(manifest["project_dir"]) / "docs/model-source-changes/app.json").is_file())
            self.assertIn("return 9", (Path(manifest["project_dir"]) / "targets/app/fixture.c").read_text(encoding="utf-8"))
            graph_payload = json.loads((Path(manifest["project_dir"]) / "docs/reconstruction-graph.json").read_text(encoding="utf-8"))
            app_source = next(node for node in graph_payload["nodes"] if node["path"] == "targets/app/fixture.c")
            self.assertEqual(app_source["sha256"], hashlib.sha256((Path(manifest["project_dir"]) / "targets/app/fixture.c").read_bytes()).hexdigest())
            self.assertEqual(manifest["knowledge_graph"]["fingerprint"], graph_payload["fingerprint"])
            self.assertEqual(manifest["automated_build"]["status"], "passed")
            self.assertTrue(manifest["automated_build"]["build_passed"])
            self.assertEqual(manifest["automated_build"]["repair_status"], "passed")
            self.assertEqual(manifest["automated_build"]["repair_iterations"], 1)
            self.assertEqual(len(build_commands), 4)

    def test_default_model_analyzer_uses_openai_http_provider_and_writes_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "native.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("app.exe", b"MZ-app")

            def runner(command):
                analysis = Path(command[list(command).index("--out") + 1])
                project = analysis / "reconstructed_fixture"
                project.mkdir(parents=True)
                (project / "CMakeLists.txt").write_text("add_library(fixture STATIC fixture.c)\n", encoding="utf-8")
                (project / "project.json").write_text("{}", encoding="utf-8")
                (project / "fixture.c").write_text("int fixture(void) { return 1; }\n", encoding="utf-8")
                return 0

            _OpenAIChatFixtureHandler.requests = []
            server = ThreadingHTTPServer(("127.0.0.1", 0), _OpenAIChatFixtureHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            environment = {
                "REVERSE_ANALYZER_PROVIDER": "openai_compatible",
                "REVERSE_ANALYZER_OPENAI_ENABLED": "1",
                "OPENAI_API_KEY": "fixture-secret",
                "OPENAI_BASE_URL": f"http://127.0.0.1:{server.server_port}/v1",
                "OPENAI_MODEL": "fixture-request-model",
                "REVERSE_ANALYZER_PROVIDER_TIMEOUT": "2",
            }
            try:
                with patch.dict(os.environ, environment, clear=False):
                    manifest = reconstruct_archive(archive, root / "analysis", runner=runner)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            self.assertEqual(len(_OpenAIChatFixtureHandler.requests), 1)
            request = _OpenAIChatFixtureHandler.requests[0]
            self.assertEqual(request["path"], "/v1/chat/completions")
            self.assertEqual(request["authorization"], "Bearer fixture-secret")
            self.assertEqual(request["body"]["model"], "fixture-request-model")
            request_context = json.loads(request["body"]["messages"][1]["content"])["context"]
            contract = request_context["strict_output_contract"]
            self.assertEqual(contract["module_id"], "app")
            self.assertEqual(contract["module_count"], 1)
            self.assertIn("responsibility", contract["required_module_fields"])
            self.assertEqual(contract["allowed_source_paths"], ["targets/app/fixture.c"])
            self.assertTrue(contract["absolute_paths_forbidden"])
            self.assertEqual(request_context["output_schema"]["source_changes"][0]["path"], "targets/app/fixture.c")
            stage = manifest["model_reconstruction"]
            self.assertEqual(stage["status"], "executed")
            self.assertEqual(stage["provider"], "openai_compatible")
            self.assertEqual(stage["model"], "fixture-http-model")
            self.assertEqual(stage["usage"], {"input_tokens": 21, "output_tokens": 8, "total_tokens": 29})
            artifact = Path(manifest["project_dir"]) / stage["artifact"]
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(payload["result"]["modules"][0]["id"], "app")
            self.assertEqual(payload["applied_change_count"], 1)
            self.assertIn("return 42", (Path(manifest["project_dir"]) / "targets/app/fixture.c").read_text(encoding="utf-8"))
            self.assertEqual(payload["calls"][0]["raw_response"], json.dumps({
                "modules": [{"id": "app", "responsibility": "HTTP fixture recovered module", "interfaces": [], "missing_implementations": [], "evidence": ["targets/app/fixture.c"]}],
                "dependency_edges": [],
                "source_changes": [{"path": "targets/app/fixture.c", "content": "int fixture(void) { return 42; }\n", "reason": "recover fixture behavior", "evidence": ["targets/app/fixture.c"]}],
            }))

    def test_model_source_change_rejects_module_escape_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "native.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("app.exe", b"MZ-app")

            def runner(command):
                analysis = Path(command[list(command).index("--out") + 1])
                project = analysis / "reconstructed_fixture"
                project.mkdir(parents=True)
                (project / "CMakeLists.txt").write_text("add_library(fixture STATIC fixture.c)\n", encoding="utf-8")
                (project / "project.json").write_text("{}", encoding="utf-8")
                (project / "fixture.c").write_text("int fixture(void) { return 1; }\n", encoding="utf-8")
                return 0

            def analyzer(context):
                target = context["targets"][0]
                evidence = next(item["path"] for item in target["source_files"] if item["path"].endswith("fixture.c"))
                return {"provider": "fixture", "result": {
                    "modules": [{"id": target["id"], "responsibility": "module", "interfaces": [], "missing_implementations": [], "evidence": [evidence]}],
                    "dependency_edges": [],
                    "source_changes": [{"path": "CMakeLists.txt", "content": "destroyed", "reason": "escape", "evidence": [evidence]}],
                }}

            manifest = reconstruct_archive(archive, root / "analysis", runner=runner, model_analyzer=analyzer)
            project = Path(manifest["project_dir"])
            self.assertEqual(manifest["model_reconstruction"]["status"], "failed")
            self.assertIn("project(reconstructed_archive_native", (project / "CMakeLists.txt").read_text(encoding="utf-8"))

    def test_model_failure_is_preserved_per_module_and_blocks_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "native.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("app.exe", b"MZ-app")

            def runner(command):
                analysis = Path(command[list(command).index("--out") + 1])
                project = analysis / "reconstructed_fixture"
                project.mkdir(parents=True)
                (project / "CMakeLists.txt").write_text("add_library(fixture STATIC fixture.c)\n", encoding="utf-8")
                (project / "project.json").write_text("{}", encoding="utf-8")
                (project / "fixture.c").write_text("int fixture;\n", encoding="utf-8")
                return 0

            manifest = reconstruct_archive(
                archive,
                root / "analysis",
                runner=runner,
                model_analyzer=lambda context: {"provider": "fixture", "content": "not-json"},
            )
            stage = manifest["model_reconstruction"]
            self.assertEqual(stage["status"], "failed")
            payload = json.loads((Path(manifest["project_dir"]) / stage["artifact"]).read_text(encoding="utf-8"))
            self.assertEqual(payload["calls"][0]["status"], "failed")
            self.assertIn("structured JSON", payload["calls"][0]["error"])


if __name__ == "__main__":
    unittest.main()
