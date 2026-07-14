from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from reverse_analyzer.source_reconstruction import reconstruct_source_project


class SourceBodyRecoveryTests(unittest.TestCase):
    def test_recovers_multiple_c_bodies_from_ghidra_artifacts_with_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_decompiler_fixture(
                root,
                [
                    (
                        "00401000",
                        "add_values",
                        "int add_values(int left, int right)",
                        "int add_values(int left, int right)\n"
                        "{\n"
                        "    return left + right;\n"
                        "}\n",
                        ".c",
                    ),
                    (
                        "00401100",
                        "multiply_values",
                        "int multiply_values(int left, int right)",
                        "int multiply_values(int left, int right)\r\n"
                        "{\r\n"
                        "    return left * right;   \r\n"
                        "}\r\n",
                        ".c",
                    ),
                ],
            )
            sample = root / "math.exe"
            sample.write_bytes(b"MZ body recovery fixture")

            result = reconstruct_source_project(
                sample,
                root / "out",
                {
                    "decompiler": fixture["decompiler"],
                    "semantic_ir": fixture["semantic_ir"],
                },
                strategy="c",
            )

            project_dir = Path(result["project_dir"])
            source = (project_dir / "src/reconstructed.c").read_text(encoding="utf-8")
            report = json.loads((project_dir / "analysis/body_recovery.json").read_text(encoding="utf-8"))

            self.assertIn("int add_values(int left, int right)", source)
            self.assertIn("return left + right;", source)
            self.assertIn("return left * right;", source)
            self.assertNotIn("TODO", source)
            self.assertEqual(report["status"], "recovered")
            self.assertEqual(report["recovered_count"], 2)
            self.assertEqual(report["placeholder_count"], 0)
            self.assertIs(report["behavior_equivalent"], False)
            self.assertIs(result["behavior_equivalent"], False)
            self.assertIs(result["stub_only"], False)

            recovered = {item["address"]: item for item in report["functions"]}
            first = recovered["0x401000"]
            self.assertEqual(first["status"], "recovered")
            self.assertEqual(first["match_basis"], "address")
            self.assertEqual(
                first["artifact"]["sha256"],
                hashlib.sha256(fixture["bodies"]["00401000"].read_bytes()).hexdigest(),
            )
            self.assertEqual(
                first["line_provenance"]["function"],
                {"start": 1, "end": 4},
            )
            self.assertEqual(first["line_provenance"]["body"], {"start": 2, "end": 4})
            self.assertGreater(first["confidence"], 0.0)
            self.assertIs(first["behavior_equivalent"], False)

            symbols = {
                item.get("address"): item
                for item in result["project"]["symbols"]
                if item.get("address")
            }
            self.assertFalse(symbols["0x401000"]["placeholder"])
            self.assertEqual(symbols["0x401000"]["body_recovery"]["status"], "recovered")
            self.assertEqual(
                symbols["0x401000"]["body_recovery"]["artifact"]["sha256"],
                first["artifact"]["sha256"],
            )
            self.assertIn("artifact:pseudocode/fn_00401000.c", symbols["0x401000"]["provenance"])

    def test_maps_cpp_overloads_stably_by_address_and_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_decompiler_fixture(
                root,
                [
                    (
                        "00402000",
                        "transform",
                        "int transform(int value)",
                        "int transform(int value)\n{\n    return value + 1;\n}\n",
                        ".cpp",
                    ),
                    (
                        "00402100",
                        "transform",
                        "double transform(double value)",
                        "double transform(double value)\n{\n    return value * 0.5;\n}\n",
                        ".cpp",
                    ),
                ],
            )
            sample = root / "overloads.exe"
            sample.write_bytes(b"MZ cpp overload fixture")

            result = reconstruct_source_project(
                sample,
                root / "out",
                {"decompiler": fixture["decompiler"], "semantic_ir": fixture["semantic_ir"]},
                strategy="cpp",
            )

            project_dir = Path(result["project_dir"])
            source = (project_dir / "src/reconstructed.cpp").read_text(encoding="utf-8")
            header = (project_dir / "include/reconstructed.hpp").read_text(encoding="utf-8")
            report = json.loads((project_dir / "analysis/body_recovery.json").read_text(encoding="utf-8"))
            overloads = [item for item in result["project"]["symbols"] if item["name"] == "transform"]

            self.assertEqual(len(overloads), 2)
            self.assertEqual({item["address"] for item in overloads}, {"0x402000", "0x402100"})
            self.assertEqual({item["body_recovery"]["match_basis"] for item in overloads}, {"address"})
            self.assertIn("int transform(int value);", header)
            self.assertIn("double transform(double value);", header)
            self.assertIn("return value + 1;", source)
            self.assertIn("return value * 0.5;", source)
            self.assertEqual(
                [item["address"] for item in report["functions"]],
                ["0x402000", "0x402100"],
            )

    def test_normalizes_and_recovers_csharp_method_body(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_decompiler_fixture(
                root,
                [
                    (
                        "06000001",
                        "Clamp",
                        "public static int Clamp(int value)",
                        "public   static int Clamp( int value )\r\n"
                        "{\r\n"
                        "    if (value < 0)\r\n"
                        "    {\r\n"
                        "        return 0;\r\n"
                        "    }\r\n"
                        "    return value;\r\n"
                        "}\r\n",
                        ".cs",
                    )
                ],
            )
            sample = root / "managed.exe"
            sample.write_bytes(b"MZ csharp fixture")

            result = reconstruct_source_project(
                sample,
                root / "out",
                {"decompiler": fixture["decompiler"], "semantic_ir": fixture["semantic_ir"]},
                strategy="csharp",
            )

            source = (Path(result["project_dir"]) / "src/Reconstructed.cs").read_text(encoding="utf-8")
            self.assertIn("public static int Clamp( int value )", source)
            self.assertIn("if (value < 0)", source)
            self.assertIn("return value;", source)
            self.assertNotIn("TODO: reconstruct behavior", source)
            recovered = next(
                item for item in result["project"]["symbols"] if item.get("address") == "0x6000001"
            )
            self.assertFalse(recovered["placeholder"])
            self.assertEqual(recovered["body_recovery"]["status"], "recovered")

    def test_malformed_decompiler_output_fails_closed_to_explicit_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_decompiler_fixture(
                root,
                [
                    (
                        "00403000",
                        "broken_parser",
                        "int broken_parser(int value)",
                        "int broken_parser(int value)\n{\n    if (value) {\n        return value;\n",
                        ".c",
                    )
                ],
            )
            sample = root / "broken.exe"
            sample.write_bytes(b"MZ malformed body fixture")

            result = reconstruct_source_project(
                sample,
                root / "out",
                {"decompiler": fixture["decompiler"], "semantic_ir": fixture["semantic_ir"]},
                strategy="c",
            )

            project_dir = Path(result["project_dir"])
            source = (project_dir / "src/reconstructed.c").read_text(encoding="utf-8")
            report = json.loads((project_dir / "analysis/body_recovery.json").read_text(encoding="utf-8"))
            function = report["functions"][0]

            self.assertEqual(function["status"], "parse_failed")
            self.assertEqual(report["parse_failure_count"], 1)
            self.assertEqual(report["recovered_count"], 0)
            self.assertIn("BODY RECOVERY UNAVAILABLE [parse_failed]", source)
            self.assertIn("int broken_parser(void)", source)
            self.assertIs(result["behavior_equivalent"], False)
            self.assertIs(result["stub_only"], True)
            self.assertFalse(any(_behavior_equivalent_true(result)))

    def test_same_name_without_identity_is_ambiguous_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pseudocode = root / "decompiler" / "pseudocode"
            pseudocode.mkdir(parents=True)
            first_path = pseudocode / "first.cpp"
            second_path = pseudocode / "second.cpp"
            first_path.write_text("int collide(int value)\n{\n    return value + 1;\n}\n", encoding="utf-8")
            second_path.write_text("int collide(int value)\n{\n    return value + 2;\n}\n", encoding="utf-8")
            sample = root / "ambiguous.exe"
            sample.write_bytes(b"MZ ambiguous body fixture")
            analysis = {
                "decompiler": {
                    "status": "ok",
                    "functions": [{"name": "collide"}],
                    "artifacts": [
                        {"name": first_path.name, "path": str(first_path), "kind": "pseudocode"},
                        {"name": second_path.name, "path": str(second_path), "kind": "pseudocode"},
                    ],
                },
                "semantic_ir": {
                    "entities": [{"id": "fn:collide", "kind": "function", "name": "collide"}]
                },
            }

            result = reconstruct_source_project(sample, root / "out", analysis, strategy="cpp")

            project_dir = Path(result["project_dir"])
            source = (project_dir / "src/reconstructed.cpp").read_text(encoding="utf-8")
            report = json.loads((project_dir / "analysis/body_recovery.json").read_text(encoding="utf-8"))
            self.assertEqual(report["ambiguous_count"], 1)
            self.assertEqual(report["recovered_count"], 0)
            self.assertIn("BODY RECOVERY UNAVAILABLE [ambiguous]", source)
            self.assertNotIn("return value + 1;", source)
            self.assertNotIn("return value + 2;", source)

    def test_body_recovery_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_decompiler_fixture(
                root,
                [
                    (
                        "00404000",
                        "deterministic",
                        "int deterministic(int value)",
                        "int deterministic(int value)\n{\n    return value ^ 7;\n}\n",
                        ".c",
                    )
                ],
            )
            sample = root / "stable.exe"
            sample.write_bytes(b"MZ deterministic fixture")
            analysis = {"decompiler": fixture["decompiler"], "semantic_ir": fixture["semantic_ir"]}

            first = reconstruct_source_project(sample, root / "first", analysis, strategy="c")
            second = reconstruct_source_project(sample, root / "second", analysis, strategy="c")
            first_dir = Path(first["project_dir"])
            second_dir = Path(second["project_dir"])

            for relative_path in ("src/reconstructed.c", "analysis/body_recovery.json", "analysis/project.json"):
                self.assertEqual(
                    (first_dir / relative_path).read_bytes(),
                    (second_dir / relative_path).read_bytes(),
                    relative_path,
                )

    @unittest.skipUnless(shutil.which("gcc"), "gcc is not available")
    def test_recovered_c_fixture_builds_with_gcc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_decompiler_fixture(
                root,
                [
                    (
                        "00405000",
                        "sum_positive",
                        "int sum_positive(int limit)",
                        "int sum_positive(int limit)\n"
                        "{\n"
                        "    int total = 0;\n"
                        "    for (int value = 1; value <= limit; ++value) {\n"
                        "        total += value;\n"
                        "    }\n"
                        "    return total;\n"
                        "}\n",
                        ".c",
                    )
                ],
            )
            sample = root / "build.exe"
            sample.write_bytes(b"MZ gcc fixture")
            result = reconstruct_source_project(
                sample,
                root / "out",
                {"decompiler": fixture["decompiler"], "semantic_ir": fixture["semantic_ir"]},
                strategy="c",
            )
            project_dir = Path(result["project_dir"])
            source = (project_dir / "src/reconstructed.c").read_text(encoding="utf-8")
            report = json.loads((project_dir / "analysis/body_recovery.json").read_text(encoding="utf-8"))
            self.assertEqual(report["recovered_count"], 1)
            self.assertEqual(report["placeholder_count"], 0)
            self.assertIn("return total;", source)
            self.assertNotIn("BODY RECOVERY UNAVAILABLE", source)
            executable = project_dir / "recovered-smoke"
            completed = subprocess.run(
                [
                    str(shutil.which("gcc")),
                    "-std=c11",
                    "-Wall",
                    "-Werror",
                    "-I",
                    str(project_dir / "include"),
                    str(project_dir / "src/main.c"),
                    str(project_dir / "src/reconstructed.c"),
                    "-o",
                    str(executable),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def _write_decompiler_fixture(
        self,
        root: Path,
        definitions: list[tuple[str, str, str, str, str]],
    ) -> dict[str, object]:
        output_dir = root / "decompiler"
        pseudocode = output_dir / "pseudocode"
        pseudocode.mkdir(parents=True)
        functions = []
        artifacts = []
        entities = []
        body_paths: dict[str, Path] = {}
        for address, name, signature, body, suffix in definitions:
            path = pseudocode / f"fn_{address}{suffix}"
            path.write_bytes(body.encode("utf-8"))
            body_paths[address] = path
            functions.append(
                {
                    "name": name,
                    "entry": address,
                    "signature": signature,
                    "confidence": 0.92,
                }
            )
            artifacts.append({"name": path.name, "path": str(path), "kind": "pseudocode"})
            entities.append(
                {
                    "id": f"function:{address}",
                    "kind": "function",
                    "name": name,
                    "confidence": 0.9,
                    "sources": ["decompiler.functions"],
                    "attributes": {"address": address, "signature": signature},
                }
            )
        (output_dir / "functions.json").write_text(
            json.dumps(functions, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return {
            "decompiler": {
                "status": "ok",
                "output_dir": str(output_dir),
                "functions": functions,
                "artifacts": artifacts,
            },
            "semantic_ir": {"schema_version": 1, "entities": entities},
            "bodies": body_paths,
        }


def _behavior_equivalent_true(value: object):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "behavior_equivalent" and item is True:
                yield True
            yield from _behavior_equivalent_true(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _behavior_equivalent_true(item)


if __name__ == "__main__":
    unittest.main()
