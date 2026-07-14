from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

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


class SourceReconstructionPipelineTests(unittest.TestCase):
    def test_all_target_stacks_emit_browsable_provenance_backed_projects(self) -> None:
        layouts = {
            "c": ("CMakeLists.txt", "src/main.c", "src/reconstructed.c"),
            "cpp": ("CMakeLists.txt", "src/main.cpp", "src/reconstructed.cpp"),
            "csharp": ("Reconstructed.Matrix.csproj", "src/Program.cs", "src/Reconstructed.cs"),
            "electron": ("package.json", "main.js", "web/index.html", "src/reconstructed.js"),
            "android-java": (
                "app/build.gradle",
                "app/src/main/AndroidManifest.xml",
                "app/src/main/java/com/reconstructed/matrix/RecoveredSymbols.java",
            ),
            "android-kotlin": (
                "app/build.gradle",
                "app/src/main/AndroidManifest.xml",
                "app/src/main/kotlin/com/reconstructed/matrix/RecoveredSymbols.kt",
            ),
            "unity-csharp": (
                "Reconstructed.Matrix.Unity.csproj",
                "Packages/manifest.json",
                "Assets/Scripts/ReconstructedBehaviour.cs",
                "Assets/Scripts/RecoveredSymbols.cs",
            ),
            "pyinstaller-python": ("pyproject.toml", "app.py", "reconstructed.py"),
        }
        evidence = {
            "semantic_ir": {
                "entities": [
                    {
                        "id": "fn:restore",
                        "kind": "function",
                        "name": "restore_state",
                        "confidence": 0.82,
                        "sources": ["decompiler.functions"],
                    }
                ]
            }
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "matrix.exe"
            sample.write_bytes(b"source reconstruction matrix")

            for stack, required_paths in layouts.items():
                with self.subTest(stack=stack):
                    result = reconstruct_source_project(sample, root / stack, evidence, strategy=stack)
                    project_dir = Path(result["project_dir"])
                    records = {item["path"]: item for item in result["project"]["files"]}

                    self.assertTrue(set(required_paths).issubset(records))
                    self.assertTrue(result["project"]["entrypoints"])
                    self.assertTrue(result["project"]["build_files"])
                    for relative_path, record in records.items():
                        self.assertTrue((project_dir / relative_path).is_file(), relative_path)
                        self.assertTrue(record["provenance"], relative_path)
                        self.assertGreaterEqual(record["confidence"], 0.0)
                        self.assertLessEqual(record["confidence"], 1.0)
                    for symbol in result["project"]["symbols"]:
                        self.assertTrue(symbol["provenance"], symbol["name"])
                        self.assertGreater(symbol["confidence"], 0.0)

                    analysis_dir = project_dir / "analysis"
                    for metadata_name in (
                        "behavior_hints.json",
                        "confidence.json",
                        "evidence_index.json",
                        "project.json",
                        "provenance.json",
                        "source_reconstruction.json",
                    ):
                        self.assertTrue((analysis_dir / metadata_name).is_file(), metadata_name)

                    if stack == "electron":
                        package = json.loads((project_dir / "package.json").read_text(encoding="utf-8"))
                        self.assertEqual(package["dependencies"], {})
                        self.assertEqual(package["devDependencies"], {})
                    elif stack == "unity-csharp":
                        behaviour = (project_dir / "Assets/Scripts/ReconstructedBehaviour.cs").read_text(
                            encoding="utf-8"
                        )
                        self.assertIn("#if UNITY_5_3_OR_NEWER", behaviour)
                        self.assertIn("UnityEngine.MonoBehaviour", behaviour)
                        manifest = json.loads((project_dir / "Packages/manifest.json").read_text(encoding="utf-8"))
                        self.assertEqual(manifest["dependencies"], {})
                    elif stack == "pyinstaller-python":
                        for source in project_dir.glob("*.py"):
                            compile(source.read_text(encoding="utf-8"), source.name, "exec")

    def test_cross_domain_evidence_is_consumed_and_semantic_graph_is_preserved(self) -> None:
        evidence = {
            "semantic_ir": {
                "schema_version": 1,
                "entities": [
                    {
                        "id": "fn:dispatch",
                        "kind": "function",
                        "name": "dispatch_message",
                        "confidence": 0.93,
                        "sources": ["decompiler.functions"],
                    }
                ],
                "relations": [
                    {
                        "id": "rel:dispatch-client",
                        "kind": "calls",
                        "source": "fn:dispatch",
                        "target": "class:client",
                        "confidence": 0.87,
                    }
                ],
                "capabilities": [{"name": "network_client", "confidence": 0.89}],
            },
            "gui_analysis": {
                "framework": "WPF",
                "confidence": 0.91,
                "runtime_tree": {
                    "windows": [
                        {
                            "name": "MainWindow",
                            "control_type": "Window",
                            "children": [{"name": "ConnectButton", "control_type": "Button"}],
                        }
                    ]
                },
                "event_handlers": ["OnConnect"],
            },
            "engine_analysis": {
                "engine": "unity-mono",
                "confidence": 0.94,
                "symbols": {
                    "mono_behaviour_symbols": ["PlayerController"],
                    "scriptable_object_symbols": ["GameSettings"],
                },
                "semantic_ir_fragment": {
                    "entities": [
                        {
                            "id": "engine:player",
                            "kind": "mono_behaviour",
                            "name": "PlayerController",
                            "confidence": 0.9,
                        }
                    ]
                },
            },
            "android_analysis": {
                "package_type": "apk",
                "confidence": 0.88,
                "framework": {"name": "native-android"},
                "manifest": {
                    "package": "com.acme.recovered",
                    "activities": [{"name": "com.acme.recovered.MainActivity"}],
                    "services": [{"name": "com.acme.recovered.SyncService"}],
                },
                "semantic_ir_fragment": {
                    "entities": [
                        {
                            "id": "android:main",
                            "kind": "android_activity",
                            "name": "com.acme.recovered.MainActivity",
                            "confidence": 0.86,
                        }
                    ]
                },
            },
            "protocol_analysis": {
                "protocols": [{"name": "protobuf", "confidence": 0.84}],
                "flows": [{"flow_id": "flow-1", "endpoint": "api.acme.test:443", "transport": "tcp"}],
                "inference": {"primary_protocol": "protobuf", "message_formats": ["protobuf", "gzip"]},
                "semantic_ir_fragment": {"capabilities": [{"name": "network_protocol"}]},
            },
            "dynamic_analysis": {
                "confidence": 0.8,
                "events": [{"api": "connect", "category": "network"}],
            },
            "functions": [{"name": "parse_packet", "confidence": 0.78}],
            "imports": [{"name": "WSAConnect"}],
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "all-evidence.exe"
            sample.write_bytes(b"MZ\x00all evidence")
            original_hash = hashlib.sha256(sample.read_bytes()).hexdigest()

            result = reconstruct_source_project(sample, root / "out", evidence, strategy="csharp")

            self.assertEqual(hashlib.sha256(sample.read_bytes()).hexdigest(), original_hash)
            index = result["evidence_index"]
            indexed = {item["name"]: item for item in index["sources"]}
            expected_sources = {
                "semantic_ir",
                "gui_analysis",
                "engine_analysis",
                "android_analysis",
                "protocol_analysis",
                "dynamic_analysis",
                "static_analysis",
            }
            self.assertEqual(set(index["present_sources"]), expected_sources)
            for source in expected_sources:
                self.assertTrue(indexed[source]["sha256"])
                self.assertTrue(indexed[source]["consumed_paths"], source)

            provenance_inputs = {item["name"]: item for item in result["provenance"]["inputs"]}
            for source in expected_sources:
                self.assertEqual(provenance_inputs[source]["consumed_paths"], indexed[source]["consumed_paths"])

            hints = result["behavior_hints"]
            self.assertIn("ConnectButton", {item["name"] for item in hints["gui_controls"]})
            self.assertIn("OnConnect", {item["name"] for item in hints["gui_handlers"]})
            self.assertIn("PlayerController", {item["name"] for item in hints["engine_symbols"]})
            self.assertIn(
                "com.acme.recovered.MainActivity",
                {item["name"] for item in hints["android_components"]},
            )
            self.assertIn("api.acme.test:443", {item["endpoint"] for item in hints["protocol_flows"]})
            self.assertIn("protobuf", {item["name"] for item in hints["protocol_formats"]})
            self.assertIn("connect", {item["name"] for item in hints["dynamic_calls"]})
            self.assertIn("WSAConnect", {item["name"] for item in hints["static_imports"]})
            expected_hint_count = sum(len(value) for value in hints.values() if isinstance(value, list))
            self.assertEqual(result["analysis"]["behavior_hint_count"], expected_hint_count)
            self.assertEqual(index["behavior_hint_count"], expected_hint_count)

            project_dir = Path(result["project_dir"])
            projection = json.loads((project_dir / "analysis/semantic_ir.json").read_text(encoding="utf-8"))
            self.assertEqual(projection["relations"][0]["kind"], "calls")
            self.assertEqual(projection["relations"][0]["source"], "fn:dispatch")
            self.assertEqual(projection["relations"][0]["target"], "class:client")
            self.assertEqual(projection["capabilities"][0]["name"], "network_client")
            self.assertEqual(projection["summary"]["relation_count"], 1)
            self.assertEqual(projection["summary"]["capability_count"], 1)

            symbols = {item["name"]: item for item in result["project"]["symbols"]}
            for name in (
                "dispatch_message",
                "PlayerController",
                "com.acme.recovered.MainActivity",
                "parse_packet",
                "OnConnect",
                "connect",
            ):
                self.assertIn(name, symbols)
                self.assertTrue(symbols[name]["provenance"])
                self.assertGreater(symbols[name]["confidence"], 0.0)

            forbidden_paths = (str(sample.resolve()).casefold(), str(root.resolve()).casefold())
            for metadata_file in (project_dir / "analysis").glob("*.json"):
                metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
                for value in _iter_strings(metadata):
                    normalized = value.casefold()
                    for forbidden in forbidden_paths:
                        self.assertNotIn(forbidden, normalized, metadata_file.name)

    def test_android_package_evidence_drives_project_layout_with_safe_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "mobile.apk"
            sample.write_bytes(b"PK\x03\x04android")

            recovered = reconstruct_source_project(
                sample,
                root / "valid",
                {
                    "android_analysis": {
                        "framework": {"name": "kotlin"},
                        "manifest": {"package": "com.acme.product"},
                    }
                },
                strategy="android-kotlin",
            )
            recovered_dir = Path(recovered["project_dir"])
            recovered_source = "app/src/main/kotlin/com/acme/product/RecoveredSymbols.kt"
            self.assertTrue((recovered_dir / recovered_source).is_file())
            app_build = (recovered_dir / "app/build.gradle").read_text(encoding="utf-8")
            self.assertIn("applicationId 'com.acme.product'", app_build)
            self.assertIn(recovered_source, {item["path"] for item in recovered["project"]["files"]})

            fallback = reconstruct_source_project(
                sample,
                root / "invalid",
                {"android_analysis": {"manifest": {"package": "9bad/package"}}},
                strategy="android-java",
            )
            fallback_dir = Path(fallback["project_dir"])
            self.assertTrue(
                (fallback_dir / "app/src/main/java/com/reconstructed/mobile/RecoveredSymbols.java").is_file()
            )

    def test_static_analysis_and_keyword_evidence_are_merged_and_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "native.exe"
            sample.write_bytes(b"native static evidence")

            result = reconstruct_source_project(
                sample,
                root / "out",
                strategy="cpp",
                static_analysis={
                    "classes": [{"name": "RecoveredController", "confidence": 0.79}],
                },
                functions=[{"name": "restore_state", "confidence": 0.86}],
                imports=[{"name": "CreateFileW"}],
            )

            symbols = {item["name"]: item for item in result["project"]["symbols"]}
            self.assertIn("RecoveredController", symbols)
            self.assertIn("restore_state", symbols)
            self.assertIn("static_analysis.classes", symbols["RecoveredController"]["provenance"])
            self.assertIn("static_analysis.functions", symbols["restore_state"]["provenance"])

            static_source = next(
                item for item in result["evidence_index"]["sources"] if item["name"] == "static_analysis"
            )
            self.assertEqual(
                set(static_source["consumed_paths"]),
                {
                    "static_analysis.classes",
                    "static_analysis.functions",
                    "static_analysis.imports",
                },
            )
            self.assertIn(
                "CreateFileW",
                {item["name"] for item in result["behavior_hints"]["static_imports"]},
            )

    def test_dashboard_summary_reads_generated_confidence_evidence_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "desktop.exe"
            sample.write_bytes(b"dashboard source reconstruction")
            generated = reconstruct_source_project(
                sample,
                root / "session",
                {
                    "semantic_ir": {
                        "entities": [{"id": "fn:start", "kind": "function", "name": "start", "confidence": 0.9}],
                        "relations": [{"source": "fn:start", "target": "ui:main", "kind": "opens"}],
                        "capabilities": [{"name": "desktop_gui"}],
                    },
                    "gui_analysis": {
                        "framework": "electron",
                        "runtime_tree": {"name": "MainWindow", "children": [{"name": "OpenButton"}]},
                    },
                },
                strategy="electron",
            )

            summary = summarize_source_reconstruction(root)

            self.assertEqual(summary["summary"]["project_total"], 1)
            project = summary["projects"][0]
            self.assertEqual(project["output_stack"], "electron-js")
            self.assertEqual(project["language"], "javascript")
            self.assertEqual(project["status"], "ok")
            self.assertEqual(project["semantic_entity_count"], 1)
            self.assertEqual(project["semantic_relation_count"], 1)
            self.assertEqual(project["semantic_capability_count"], 1)
            self.assertEqual(set(project["evidence_used"]), {"semantic_ir", "gui_analysis"})
            self.assertGreater(project["confidence"], 0.0)
            self.assertIn(project["confidence_level"], {"low", "medium", "high"})
            self.assertGreater(project["behavior_hint_count"], 0)
            self.assertIn("main.js", project["entrypoints"])
            self.assertIn("package.json", project["build_files"])
            self.assertIn("analysis/provenance.json", project["artifacts"])
            self.assertEqual(project["provenance"]["sample"]["name"], "desktop.exe")
            self.assertEqual(project["provenance"]["sample"]["sha256"], generated["provenance"]["sample"]["sha256"])
            self.assertTrue(
                any(item["name"] == "gui_analysis" and item["consumed_paths"] for item in project["provenance"]["inputs"])
            )
            serialized = json.dumps(summary, sort_keys=True)
            self.assertNotIn(str(root.resolve()), serialized)
            self.assertFalse(any(Path(path).is_absolute() for path in project["artifacts"]))


if __name__ == "__main__":
    unittest.main()
