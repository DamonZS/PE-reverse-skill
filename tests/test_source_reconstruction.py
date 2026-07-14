from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reverse_analyzer.source_reconstruction import reconstruct_source_project, summarize_source_reconstruction


def _iter_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _iter_strings(key)
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


class SourceReconstructionSummaryTests(unittest.TestCase):
    def test_discovers_c_project_and_reports_only_workspace_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            project = workspace / "reports" / "sample" / "reconstructed_sample"
            self._write(project / "analysis" / "summary.json", {"function_count": 4, "dynamic_evidence_count": 2})
            self._write(project / "analysis" / "module_map.json", {"modules": {"network": [], "core": []}})
            self._write(project / "analysis" / "reconstruction_plan.json", {"tasks": [{"name": "dynamic_correlation"}]})
            self._write(project / "analysis" / "dynamic_evidence.json", [{"api": "connect"}])
            self._write(
                project / "analysis" / "semantic_ir.json",
                {"summary": {"entity_count": 4, "relation_count": 3, "capability_count": 2}},
            )
            self._write(
                project / "analysis" / "reconstruction_verification.json",
                {"status": "ok", "score": 0.91, "coverage": {"semantic_coverage": 1.0, "module_coverage": 1.0}},
            )
            (project / "src").mkdir(parents=True, exist_ok=True)
            (project / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (project / "src" / "network.c").write_text("void network(void) {}\n", encoding="utf-8")
            (project / "assets").mkdir(parents=True, exist_ok=True)
            (project / "assets" / "logo.png").write_bytes(b"PNG")
            (project / "CMakeLists.txt").write_text("project(sample)\n", encoding="utf-8")
            (project / "README.md").write_text("# Sample\n", encoding="utf-8")

            result = summarize_source_reconstruction(workspace)

            self.assertEqual(result["summary"]["project_total"], 1)
            self.assertEqual(result["summary"]["source_file_total"], 2)
            self.assertEqual(result["summary"]["resource_file_total"], 1)
            self.assertEqual(result["summary"]["function_total"], 4)
            self.assertEqual(result["summary"]["dynamic_evidence_total"], 1)
            project_data = result["projects"][0]
            self.assertEqual(project_data["relative_path"], "reports/sample/reconstructed_sample")
            self.assertEqual(project_data["language"], "c")
            self.assertEqual(project_data["module_count"], 2)
            self.assertEqual(project_data["next_task"], "dynamic_correlation")
            self.assertEqual(project_data["semantic_entity_count"], 4)
            self.assertEqual(project_data["semantic_capability_count"], 2)
            self.assertEqual(project_data["verification_score"], 0.91)
            self.assertEqual(result["summary"]["semantic_entity_total"], 4)
            self.assertEqual(result["summary"]["verified_project_total"], 1)
            self.assertEqual(project_data["entrypoints"], ["CMakeLists.txt", "src/main.c"])
            self.assertIn("int main", project_data["source_files"][0]["preview"])
            self.assertFalse(any(str(workspace) in item["path"] for item in project_data["source_files"]))

    def test_gui_project_and_malformed_optional_metadata_are_graceful(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            project = workspace / "experiments" / "run-1" / "analysis" / "reconstructed_gui"
            self._write(project / "analysis" / "gui_strategy.json", {"output_stack": "wpf", "status": "ok", "stub_only": True})
            (project / "analysis" / "gui_analysis.json").parent.mkdir(parents=True, exist_ok=True)
            (project / "analysis" / "gui_analysis.json").write_text("{not-json", encoding="utf-8")
            (project / "src").mkdir(parents=True, exist_ok=True)
            (project / "src" / "MainWindow.xaml").write_text("<Window />\n", encoding="utf-8")

            result = summarize_source_reconstruction(workspace)

            self.assertEqual(result["summary"]["project_total"], 1)
            project_data = result["projects"][0]
            self.assertEqual(project_data["output_stack"], "wpf")
            self.assertEqual(project_data["language"], "xaml")
            self.assertEqual(project_data["status"], "ok")
            self.assertTrue(project_data["stub_only"])
            self.assertEqual(result["diagnostics"]["malformed_metadata"], 1)

    def test_missing_workspace_returns_empty_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"

            result = summarize_source_reconstruction(missing)

            self.assertEqual(result["summary"]["project_total"], 0)
            self.assertEqual(result["projects"], [])
            self.assertEqual(result["diagnostics"]["workspace_unavailable"], str(missing))

    def test_source_directories_are_prioritized_before_large_resource_trees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            project = workspace / "reports" / "sample" / "reconstructed_sample"
            (project / "assets").mkdir(parents=True, exist_ok=True)
            (project / "assets" / "one.bin").write_bytes(b"1")
            (project / "assets" / "two.bin").write_bytes(b"2")
            (project / "src").mkdir(parents=True, exist_ok=True)
            (project / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

            with patch("reverse_analyzer.source_reconstruction._MAX_FILES_PER_PROJECT", 2):
                result = summarize_source_reconstruction(workspace)

            project_data = result["projects"][0]
            self.assertEqual(project_data["source_file_count"], 1)
            self.assertEqual(project_data["source_files"][0]["path"], "src/main.c")
            self.assertTrue(project_data["source_files_truncated"])
            self.assertEqual(result["diagnostics"]["truncated_file_lists"], 1)

    @staticmethod
    def _write(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")


class SourceProjectGenerationTests(unittest.TestCase):
    def test_auto_strategy_selects_all_supported_stacks_deterministically(self) -> None:
        cases = (
            ("c", {}, "sample.bin"),
            ("cpp", {"gui_analysis": {"framework": "Qt", "confidence": 0.86}}, "sample.exe"),
            ("csharp", {"gui_analysis": {"framework": "WPF", "confidence": 0.91}}, "sample.exe"),
            ("electron", {"gui_analysis": {"framework": "Electron", "output_stack": "electron"}}, "sample.exe"),
            ("android-java", {"android_analysis": {"package_type": "apk", "framework": "java"}}, "sample.bin"),
            ("android-kotlin", {"android_analysis": {"package_type": "apk", "framework": "kotlin"}}, "sample.bin"),
            ("unity-csharp", {"engine_analysis": {"engine": "unity-mono", "confidence": 0.96}}, "sample.exe"),
            (
                "pyinstaller-python",
                {"dynamic_analysis": {"events": [{"module": "PyInstaller", "path": "PYZ-00.pyz"}]}},
                "sample.exe",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (expected, evidence, filename) in enumerate(cases):
                with self.subTest(stack=expected):
                    sample = root / f"case-{index}" / filename
                    sample.parent.mkdir(parents=True)
                    sample.write_bytes(b"sample input")
                    result = reconstruct_source_project(sample, root / f"out-{index}", evidence)

                    self.assertEqual(result["status"], "ok")
                    self.assertEqual(result["analysis"]["selected_stack"], expected)
                    self.assertEqual(result["project"]["stack"], expected)
                    self.assertTrue(result["project"]["files"])
                    self.assertTrue(Path(result["project_dir"]).is_dir())

    def test_semantic_symbols_and_every_generated_file_have_traceable_metadata(self) -> None:
        semantic_ir = {
            "schema_version": 1,
            "entities": [
                {
                    "id": "fn:connect",
                    "kind": "function",
                    "name": "connect_to_server",
                    "confidence": 0.88,
                    "sources": ["decompiler.functions", "dynamic.events"],
                },
                {
                    "id": "class:session",
                    "kind": "class",
                    "name": "SessionController",
                    "confidence": 0.72,
                    "sources": ["gui.state_machine"],
                },
            ],
            "relations": [{"source": "fn:connect", "target": "class:session", "kind": "member_of"}],
            "capabilities": [{"name": "network_client", "confidence": 0.84}],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "client.exe"
            sample.write_bytes(b"MZ\x00semantic input")

            result = reconstruct_source_project(
                sample,
                root / "out",
                {
                    "semantic_ir": semantic_ir,
                    "gui_analysis": {"framework": "WPF", "confidence": 0.9},
                    "protocol_analysis": {
                        "protocols": [{"name": "http", "confidence": 0.92}],
                        "flows": [{"endpoint": "https://example.test/api", "kind": "url"}],
                    },
                },
            )

            self.assertEqual(set(result) & {"analysis", "provenance", "confidence", "project"}, {
                "analysis", "provenance", "confidence", "project"
            })
            symbols = {item["name"]: item for item in result["project"]["symbols"]}
            for name in ("connect_to_server", "SessionController"):
                self.assertIn(name, symbols)
                self.assertTrue(symbols[name]["provenance"])
                self.assertGreater(symbols[name]["confidence"], 0.0)
                self.assertTrue(symbols[name]["placeholder"])
            self.assertAlmostEqual(symbols["connect_to_server"]["confidence"], 0.88)
            self.assertIn("decompiler.functions", symbols["connect_to_server"]["provenance"])
            for generated in result["project"]["files"]:
                self.assertTrue(generated["provenance"], generated["path"])
                self.assertGreaterEqual(generated["confidence"], 0.0)
                self.assertLessEqual(generated["confidence"], 1.0)
                self.assertTrue((Path(result["project_dir"]) / generated["path"]).is_file())

            project_json = json.loads((Path(result["project_dir"]) / "analysis" / "project.json").read_text(encoding="utf-8"))
            self.assertEqual(project_json, result["project"])
            self.assertEqual(result["provenance"]["sample"]["name"], "client.exe")
            for metadata_file in (Path(result["project_dir"]) / "analysis").glob("*.json"):
                metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
                for item in _iter_strings(metadata):
                    self.assertNotIn(str(sample.resolve()).casefold(), item.casefold(), metadata_file.name)

            recovered_source = (Path(result["project_dir"]) / "src" / "Reconstructed.cs").read_text(
                encoding="utf-8"
            )
            self.assertIn("Evidence refs: semantic_ir.entities", recovered_source)
            self.assertIn("confidence=0.880", recovered_source)

    def test_each_stack_has_build_layout_entrypoint_and_evidence_backed_placeholders(self) -> None:
        layouts = {
            "c": ("CMakeLists.txt", "src/main.c", "src/reconstructed.c"),
            "cpp": ("CMakeLists.txt", "src/main.cpp", "src/reconstructed.cpp"),
            "csharp": ("Reconstructed.Layout.csproj", "src/Program.cs", "src/Reconstructed.cs"),
            "electron": ("package.json", "main.js", "src/reconstructed.js"),
            "android-java": (
                "app/build.gradle",
                "app/src/main/AndroidManifest.xml",
                "app/src/main/java/com/reconstructed/layout/RecoveredSymbols.java",
            ),
            "android-kotlin": (
                "app/build.gradle",
                "app/src/main/AndroidManifest.xml",
                "app/src/main/kotlin/com/reconstructed/layout/RecoveredSymbols.kt",
            ),
            "unity-csharp": (
                "Reconstructed.Layout.Unity.csproj",
                "Assets/Scripts/ReconstructedBehaviour.cs",
                "Assets/Scripts/RecoveredSymbols.cs",
            ),
            "pyinstaller-python": ("pyproject.toml", "app.py", "reconstructed.py"),
        }
        evidence = {
            "semantic_ir": {
                "entities": [
                    {
                        "id": "fn:dispatch",
                        "kind": "function",
                        "name": "dispatch_request",
                        "confidence": 0.81,
                        "sources": ["decompiler:functions:0x401000"],
                    },
                    {
                        "id": "class:state",
                        "kind": "class",
                        "name": "RuntimeState",
                        "confidence": 0.74,
                        "sources": ["rtti:RuntimeState"],
                    },
                ]
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "layout.exe"
            sample.write_bytes(b"layout")

            for stack, expected_paths in layouts.items():
                with self.subTest(stack=stack):
                    result = reconstruct_source_project(
                        sample,
                        root / stack,
                        evidence,
                        strategy=stack,
                    )
                    project_dir = Path(result["project_dir"])
                    recorded_paths = {item["path"] for item in result["project"]["files"]}
                    self.assertTrue(set(expected_paths).issubset(recorded_paths))
                    self.assertTrue(result["project"]["entrypoints"])
                    self.assertTrue(result["project"]["build_files"])
                    for relative_path in (*result["project"]["entrypoints"], *result["project"]["build_files"]):
                        self.assertTrue((project_dir / relative_path).is_file(), relative_path)

                    placeholder_source = (project_dir / expected_paths[-1]).read_text(encoding="utf-8")
                    self.assertIn("TODO", placeholder_source)
                    self.assertIn("Evidence refs: semantic_ir.entities", placeholder_source)
                    self.assertIn("confidence=0.810", placeholder_source)

                    if stack == "electron":
                        package = json.loads((project_dir / "package.json").read_text(encoding="utf-8"))
                        self.assertEqual(package["dependencies"], {})
                    elif stack == "pyinstaller-python":
                        for path in project_dir.glob("*.py"):
                            compile(path.read_text(encoding="utf-8"), path.name, "exec")

    def test_malformed_evidence_is_diagnosed_and_degrades_gracefully(self) -> None:
        recursive: dict[str, object] = {}
        recursive["self"] = recursive
        malformed = {
            "semantic_ir": "entities should be a mapping",
            "gui_analysis": ["not", "a", "mapping"],
            "engine_analysis": b"not-json",
            "android_analysis": 42,
            "protocol_analysis": object(),
            "dynamic_analysis": {"events": [recursive], "confidence": float("nan")},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "malformed.exe"
            sample.write_bytes(b"malformed")

            result = reconstruct_source_project(sample, root / "out", malformed)
            top_level = reconstruct_source_project(sample, root / "top-level", ["bad"])  # type: ignore[arg-type]

            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["analysis"]["selected_stack"], "c")
            self.assertEqual(result["confidence"]["level"], "low")
            self.assertGreaterEqual(len(result["analysis"]["diagnostics"]), 5)
            self.assertIn("malformed_evidence", {item["code"] for item in result["analysis"]["diagnostics"]})
            self.assertEqual(result["analysis"]["evidence"]["dynamic_analysis"]["event_count"], 1)
            self.assertEqual(top_level["analysis"]["selected_stack"], "c")
            self.assertEqual(top_level["analysis"]["diagnostics"][0]["code"], "malformed_analysis")
            json.dumps(result, allow_nan=False, sort_keys=True)

    def test_no_evidence_emits_low_confidence_compilable_c_placeholder_without_touching_sample(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "unknown.exe"
            sample.write_bytes(b"MZ\x00unknown")
            before = hashlib.sha256(sample.read_bytes()).hexdigest()

            result = reconstruct_source_project(sample, root / "out")

            after = hashlib.sha256(sample.read_bytes()).hexdigest()
            project_dir = Path(result["project_dir"])
            self.assertEqual(before, after)
            self.assertEqual(result["analysis"]["selected_stack"], "c")
            self.assertEqual(result["confidence"]["level"], "low")
            self.assertTrue(result["analysis"]["placeholders"])
            self.assertIn("project(", (project_dir / "CMakeLists.txt").read_text(encoding="utf-8"))
            self.assertIn("int main(void)", (project_dir / "src" / "main.c").read_text(encoding="utf-8"))
            self.assertIn("TODO", (project_dir / "src" / "reconstructed.c").read_text(encoding="utf-8"))

    def test_electron_and_python_skeletons_need_no_generator_or_runtime_packages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "packed.exe"
            sample.write_bytes(b"packed")
            with patch("subprocess.run", side_effect=AssertionError("external process used")):
                electron = reconstruct_source_project(
                    sample,
                    root / "electron",
                    {"gui_analysis": {"framework": "electron"}},
                )
                python = reconstruct_source_project(
                    sample,
                    root / "python",
                    {"dynamic_analysis": {"loader": "PyInstaller", "archive": "PYZ"}},
                )

            package = json.loads((Path(electron["project_dir"]) / "package.json").read_text(encoding="utf-8"))
            self.assertEqual(package.get("dependencies"), {})
            self.assertTrue((Path(electron["project_dir"]) / "web" / "index.html").is_file())
            app_source = (Path(python["project_dir"]) / "app.py").read_text(encoding="utf-8")
            compile(app_source, "app.py", "exec")
            self.assertNotIn("site-packages", app_source)

    def test_metadata_is_repeatable_and_oversized_samples_are_rejected_before_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "repeat.exe"
            sample.write_bytes(b"repeatable")
            evidence = {"engine_analysis": {"engine": "unity-il2cpp", "confidence": 0.94}}

            first = reconstruct_source_project(sample, root / "out", evidence)
            metadata_paths = (
                "analysis/source_reconstruction.json",
                "analysis/provenance.json",
                "analysis/confidence.json",
                "analysis/project.json",
            )
            first_contents = {
                name: (Path(first["project_dir"]) / name).read_text(encoding="utf-8") for name in metadata_paths
            }
            second = reconstruct_source_project(sample, root / "out", evidence)
            second_contents = {
                name: (Path(second["project_dir"]) / name).read_text(encoding="utf-8") for name in metadata_paths
            }
            self.assertEqual(first_contents, second_contents)

            oversized = root / "too-large.bin"
            oversized.write_bytes(b"12345")
            with patch("reverse_analyzer.source_reconstruction._MAX_RECONSTRUCTION_SAMPLE_BYTES", 4):
                with self.assertRaisesRegex(ValueError, "sample exceeds"):
                    reconstruct_source_project(oversized, root / "oversized-out")
            self.assertFalse((root / "oversized-out").exists())


if __name__ == "__main__":
    unittest.main()
