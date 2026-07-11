import json
import tempfile
from collections import UserDict
import unittest
from pathlib import Path

from reverse_analyzer.tools.reconstruct import reconstruct_project


class ReconstructProjectTests(unittest.TestCase):
    def test_minimal_input_generates_stub_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")

            result = reconstruct_project(sample, root / "out")
            project_dir = Path(result["project_dir"])

            self.assertEqual(result["status"], "ok")
            self.assertTrue(project_dir.is_dir())
            self.assertTrue((project_dir / "CMakeLists.txt").is_file())
            self.assertTrue((project_dir / "src" / "main.c").is_file())
            self.assertTrue((project_dir / "src" / "functions.c").is_file())
            self.assertTrue((project_dir / "include" / "imports.h").is_file())
            self.assertTrue((project_dir / "analysis" / "call_graph.json").is_file())
            self.assertTrue((project_dir / "analysis" / "strings_xrefs.json").is_file())
            self.assertTrue((project_dir / "analysis" / "imports_xrefs.json").is_file())
            self.assertTrue((project_dir / "analysis" / "dynamic_evidence.json").is_file())
            self.assertTrue((project_dir / "analysis" / "module_map.json").is_file())
            self.assertTrue((project_dir / "analysis" / "reconstruction_plan.json").is_file())
            self.assertTrue((project_dir / "analysis" / "summary.json").is_file())
            self.assertTrue((project_dir / "README.md").is_file())
            self.assertIn(str(project_dir / "README.md"), result["generated_files"])

            summary = json.loads((project_dir / "analysis" / "summary.json").read_text(encoding="utf-8"))
            self.assertTrue(summary["stub_only"])
            self.assertEqual(summary["function_count"], 0)
            self.assertEqual(summary["dynamic_evidence_count"], 0)
            self.assertEqual(summary["modules"]["module_count"], 0)
            self.assertEqual(summary["modules"]["priorities"], [])
            self.assertEqual(summary["reconstruction_plan"]["task_count"], 0)

    def test_analysis_functions_and_imports_populate_stub_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "specimen.bin"
            sample.write_bytes(b"MZ")
            analysis = {
                "functions": [
                    {
                        "name": "entry",
                        "entry": "00401000",
                        "signature": "int entry(void)",
                        "body_size": 42,
                        "calls": [{"name": "helper"}, {"name": "GetProcAddress"}],
                    },
                    {"name": "helper-routine"},
                ],
                "imports": [
                    {
                        "dll": "KERNEL32.dll",
                        "functions": [{"name": "LoadLibraryA"}],
                    },
                    {
                        "dll": "WINHTTP.dll",
                        "functions": [{"name": "WinHttpOpen"}],
                    },
                ],
                "call_graph": {"nodes": [{"name": "entry"}], "edges": [{"source": "00401000", "target": "00402000"}]},
                "strings_xrefs": [
                    {
                        "address": "00405000",
                        "value": "https://example.test/ping",
                        "xref_count": 1,
                        "functions": [{"name": "entry", "entry": "00401000"}],
                        "xrefs": [{"from_address": "00401010", "function_name": "entry", "function_entry": "00401000", "ref_type": "DATA"}],
                    },
                    {
                        "address": "00405020",
                        "value": "User-Agent: reverse-analyzer",
                        "xref_count": 1,
                        "functions": [{"name": "helper-routine", "entry": "00402000"}],
                        "xrefs": [{"from_address": "00402010", "function_name": "helper-routine", "function_entry": "00402000", "ref_type": "DATA"}],
                    },
                ],
                "imports_xrefs": [
                    {
                        "library": "KERNEL32.dll",
                        "label": "GetProcAddress",
                        "address": "EXTERNAL:0001",
                        "xref_count": 1,
                        "functions": [{"name": "entry", "entry": "00401000"}],
                    },
                    {
                        "library": "WINHTTP.dll",
                        "label": "WinHttpOpen",
                        "address": "EXTERNAL:0002",
                        "xref_count": 1,
                        "functions": [{"name": "helper-routine", "entry": "00402000"}],
                    },
                ],
                "summary": {
                    "function_count": 2,
                    "source": "test",
                    "ghidra": {
                        "program": "specimen.bin",
                        "language": "x86:LE:32:default",
                        "compiler": "windows",
                        "image_base": "00400000",
                    },
                },
            }

            result = reconstruct_project(sample, root / "out", analysis=analysis)
            project_dir = Path(result["project_dir"])
            functions_c = (project_dir / "src" / "functions.c").read_text(encoding="utf-8")
            loader_c = (project_dir / "src" / "loader.c").read_text(encoding="utf-8")
            network_c = (project_dir / "src" / "network.c").read_text(encoding="utf-8")
            imports_h = (project_dir / "include" / "imports.h").read_text(encoding="utf-8")
            readme = (project_dir / "README.md").read_text(encoding="utf-8")
            module_map = json.loads((project_dir / "analysis" / "module_map.json").read_text(encoding="utf-8"))
            reconstruction_plan = json.loads((project_dir / "analysis" / "reconstruction_plan.json").read_text(encoding="utf-8"))
            summary = json.loads((project_dir / "analysis" / "summary.json").read_text(encoding="utf-8"))

            self.assertIn("capability modules: loader, network", functions_c)
            self.assertIn("int entry(void)", loader_c)
            self.assertIn("metadata: entry=00401000, signature=int entry(void), body_size=42, calls=helper, GetProcAddress", loader_c)
            self.assertIn("recovered calls: helper, GetProcAddress", loader_c)
            self.assertIn("int helper_routine(void)", network_c)
            self.assertIn("inferred module: network", network_c)
            self.assertIn("Library: KERNEL32.dll", imports_h)
            self.assertIn("Library: WINHTTP.dll", imports_h)
            self.assertIn("LoadLibraryA", imports_h)
            self.assertIn("GetProcAddress", imports_h)
            self.assertIn("WinHttpOpen", imports_h)
            self.assertEqual(module_map["files"], ["loader", "network"])
            self.assertEqual(summary["analysis_summary"]["source"], "test")
            self.assertEqual(summary["call_graph"]["edge_count"], 1)
            self.assertEqual(summary["string_xref_count"], 2)
            self.assertEqual(summary["import_xref_count"], 2)
            self.assertEqual(summary["string_xref_function_count"], 2)
            self.assertEqual(summary["import_xref_function_count"], 2)
            self.assertEqual(summary["modules"]["module_count"], 2)
            self.assertEqual(summary["modules"]["function_count_by_module"]["loader"], 1)
            self.assertEqual(summary["modules"]["function_count_by_module"]["network"], 1)
            self.assertEqual(summary["modules"]["priorities"][0]["module"], "loader")
            self.assertEqual(summary["modules"]["high_value_functions"][0]["name"], "entry")
            self.assertEqual(summary["reconstruction_plan"]["task_count"], 2)
            self.assertEqual(summary["reconstruction_plan"]["next_task"], "reconstruct_loader")
            self.assertEqual(reconstruction_plan["tasks"][0]["name"], "reconstruct_loader")
            self.assertTrue(any(subtask["name"].startswith("recover_") for subtask in reconstruction_plan["tasks"][0]["subtasks"]))
            self.assertEqual(summary["ghidra"]["language"], "x86:LE:32:default")
            self.assertEqual(summary["top_strings"][0]["functions"], ["entry"])
            self.assertEqual(summary["top_imports"][0]["functions"], ["entry"])
            self.assertIn("Call graph edges: 1", readme)
            self.assertIn("String cross-references: 2", readme)
            self.assertIn("Functions with string references: 2", readme)
            self.assertIn("Capability modules: 2", readme)
            self.assertIn("Dynamic evidence items: 0", readme)
            self.assertIn("loader: 1 function stub(s)", readme)
            self.assertIn("## Module priority order", readme)
            self.assertIn("## High-value functions", readme)
            self.assertIn("## Reconstruction plan", readme)
            self.assertIn("Next task: reconstruct_loader", readme)
            self.assertIn("Language: x86:LE:32:default", readme)

    def test_dynamic_evidence_drives_reconstruction_modules_without_static_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "dynamic.exe"
            sample.write_bytes(b"MZ")
            analysis = {
                "dynamic_evidence": [
                    {
                        "backend": "frida",
                        "module": "network",
                        "kind": "api",
                        "name": "connect",
                        "count": 4,
                        "detail": "socket connect observed",
                    },
                    {
                        "backend": "procmon",
                        "module": "process",
                        "kind": "operation",
                        "name": "Process Create",
                        "count": 2,
                        "detail": "child process created",
                    },
                ]
            }

            result = reconstruct_project(sample, root / "out", analysis=analysis)
            project_dir = Path(result["project_dir"])
            module_map = json.loads((project_dir / "analysis" / "module_map.json").read_text(encoding="utf-8"))
            reconstruction_plan = json.loads((project_dir / "analysis" / "reconstruction_plan.json").read_text(encoding="utf-8"))
            summary = json.loads((project_dir / "analysis" / "summary.json").read_text(encoding="utf-8"))
            readme = (project_dir / "README.md").read_text(encoding="utf-8")

            self.assertTrue((project_dir / "src" / "network.c").is_file())
            self.assertTrue((project_dir / "src" / "process.c").is_file())
            self.assertEqual(summary["dynamic_evidence_count"], 2)
            self.assertIn("network", module_map["files"])
            self.assertIn("process", module_map["files"])
            self.assertEqual(module_map["priorities"][0]["module"], "network")
            self.assertGreater(module_map["priorities"][0]["dynamic_priority"], 0)
            self.assertIn("dynamic_evidence_by_module", summary["modules"])
            self.assertIn("## Dynamic evidence by module", readme)
            self.assertIn("connect", readme)
            task_names = [task["name"] for task in reconstruction_plan["tasks"]]
            self.assertIn("reconstruct_network", task_names)
            network_task = next(task for task in reconstruction_plan["tasks"] if task["name"] == "reconstruct_network")
            self.assertTrue(any(subtask["metadata"].get("kind") == "dynamic_correlation" for subtask in network_task["subtasks"]))

    def test_semantic_ir_is_preserved_for_later_reconstruction_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "semantic.exe"
            sample.write_bytes(b"MZ")
            semantic_ir = {
                "schema_version": 1,
                "entities": [
                    {"id": "function:entry", "kind": "function", "name": "entry"},
                    {"id": "api:connect", "kind": "api", "name": "connect"},
                ],
                "relations": [
                    {"id": "edge:entry-connect", "type": "calls", "source": "function:entry", "target": "api:connect"}
                ],
                "capabilities": [
                    {"id": "capability:network", "name": "network", "category": "network", "entity_ids": ["api:connect"]}
                ],
                "summary": {"entity_count": 2, "relation_count": 1, "capability_count": 1},
            }

            result = reconstruct_project(
                sample,
                root / "out",
                analysis={
                    "functions": [{"name": "entry", "calls": ["connect"]}],
                    "semantic_ir": semantic_ir,
                },
            )
            project_dir = Path(result["project_dir"])
            persisted = json.loads((project_dir / "analysis" / "semantic_ir.json").read_text(encoding="utf-8"))
            summary = json.loads((project_dir / "analysis" / "summary.json").read_text(encoding="utf-8"))

            self.assertEqual(persisted, semantic_ir)
            self.assertEqual(result["semantic_ir"]["entity_count"], 2)
            self.assertEqual(summary["semantic_ir"]["capability_count"], 1)
            self.assertTrue(any(item["name"] == "analysis/semantic_ir.json" for item in result["artifacts"]))
            self.assertIn("Semantic IR", (project_dir / "README.md").read_text(encoding="utf-8"))

    def test_semantic_ir_malformed_collections_and_nonfinite_values_are_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "malformed.exe"
            sample.write_bytes(b"MZ")
            semantic_ir = UserDict(
                {
                    "schema_version": 1,
                    "entities": 7,
                    "relations": None,
                    "capabilities": True,
                    "metadata": {
                        "not_a_number": float("nan"),
                        "positive_infinity": float("inf"),
                        "negative_infinity": float("-inf"),
                    },
                }
            )

            result = reconstruct_project(sample, root / "out", analysis={"semantic_ir": semantic_ir})
            project_dir = Path(result["project_dir"])
            persisted_text = (project_dir / "analysis" / "semantic_ir.json").read_text(encoding="utf-8")
            persisted = json.loads(persisted_text)

            self.assertEqual(
                result["semantic_ir"],
                {"schema_version": 1, "entity_count": 0, "relation_count": 0, "capability_count": 0},
            )
            self.assertEqual(persisted["entities"], 7)
            self.assertIsNone(persisted["relations"])
            self.assertTrue(persisted["capabilities"])
            self.assertEqual(persisted["metadata"], {
                "not_a_number": None,
                "positive_infinity": None,
                "negative_infinity": None,
            })
            self.assertNotIn("NaN", persisted_text)
            self.assertNotIn("Infinity", persisted_text)

    def test_semantic_ir_persistence_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "deterministic.exe"
            sample.write_bytes(b"MZ")
            first_ir = {
                "schema_version": 1,
                "entities": [{"id": "function:entry", "kind": "function", "metadata": {"z": 2, "a": 1}}],
                "relations": [{"id": "edge:entry-api", "source": "function:entry", "target": "api:connect"}],
                "capabilities": [{"id": "capability:network", "name": "network", "entity_ids": ["api:connect"]}],
                "summary": {"entity_count": 1, "relation_count": 1, "capability_count": 1},
            }
            second_ir = {
                "summary": {"capability_count": 1, "relation_count": 1, "entity_count": 1},
                "capabilities": [{"entity_ids": ["api:connect"], "name": "network", "id": "capability:network"}],
                "relations": [{"target": "api:connect", "source": "function:entry", "id": "edge:entry-api"}],
                "entities": [{"metadata": {"a": 1, "z": 2}, "kind": "function", "id": "function:entry"}],
                "schema_version": 1,
            }

            first_result = reconstruct_project(sample, root / "out-first", analysis={"semantic_ir": first_ir})
            second_result = reconstruct_project(sample, root / "out-second", analysis={"semantic_ir": second_ir})
            first_bytes = (Path(first_result["project_dir"]) / "analysis" / "semantic_ir.json").read_bytes()
            second_bytes = (Path(second_result["project_dir"]) / "analysis" / "semantic_ir.json").read_bytes()

            self.assertEqual(first_bytes, second_bytes)
            self.assertEqual(json.loads(first_bytes), json.loads(second_bytes))

    def test_returns_artifacts_list_for_generated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "artifact.exe"
            sample.write_bytes(b"MZ")

            result = reconstruct_project(sample, root / "out")

            self.assertIsInstance(result["artifacts"], list)
            self.assertEqual(len(result["artifacts"]), 12)
            self.assertTrue(any(item["name"] == "src/functions.c" for item in result["artifacts"]))
            self.assertTrue(any(item["name"] == "analysis/call_graph.json" for item in result["artifacts"]))
            self.assertTrue(any(item["name"] == "analysis/dynamic_evidence.json" for item in result["artifacts"]))
            self.assertTrue(any(item["name"] == "analysis/module_map.json" for item in result["artifacts"]))
            self.assertTrue(any(item["name"] == "analysis/reconstruction_plan.json" for item in result["artifacts"]))
            self.assertTrue(any(item["kind"] == "analysis" for item in result["artifacts"]))


if __name__ == "__main__":
    unittest.main()
