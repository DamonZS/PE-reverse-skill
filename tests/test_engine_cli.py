import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from reverse_analyzer.evidence import verify_manifest
from tests.test_engine_analysis import _write_unity_mono_sample


ROOT = Path(__file__).resolve().parents[1]


def run_engine_analyze(sample: Path, out_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "reverse_analyzer",
            "engine",
            "analyze",
            str(sample),
            "--out",
            str(out_dir),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )


class EngineCliIntegrationTests(unittest.TestCase):
    def test_unity_fixture_writes_engine_and_platform_core_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = _write_unity_mono_sample(root)
            out_dir = root / "analysis"

            result = run_engine_analyze(sample, out_dir)

            self.assertEqual(result.returncode, 0, result.stderr)
            cli_payload = json.loads(result.stdout)
            self.assertEqual(cli_payload["status"], "succeeded")

            report_path = out_dir / "report.json"
            manifest_path = out_dir / "evidence-manifest.json"
            expected_engine_artifacts = {
                "engine/fingerprint.json",
                "engine/metadata.json",
                "engine/assets.json",
                "engine/symbols.json",
                "engine/native_mapping.json",
                "engine/sdk_skeleton.json",
                "engine/semantic_ir_fragment.json",
            }
            expected_output_files = {
                "report.json",
                "semantic_ir.json",
                "evidence_graph.json",
                "evidence-manifest.json",
                *expected_engine_artifacts,
            }
            for relative_path in expected_output_files:
                self.assertTrue((out_dir / relative_path).is_file(), relative_path)

            report = json.loads(report_path.read_text(encoding="utf-8"))
            engine = report["engine_analysis"]
            self.assertEqual(engine["status"], "ok")
            self.assertEqual(engine["engine"], "unity-mono")
            self.assertGreaterEqual(engine["metadata"]["managed_assembly_count"], 2)
            self.assertEqual(report["semantic_ir"]["schema_version"], 1)
            evidence_graph = json.loads(
                (out_dir / "evidence_graph.json").read_text(encoding="utf-8")
            )
            self.assertTrue(
                any(
                    node.get("node_type") == "engine_analysis"
                    for node in evidence_graph["nodes"]
                )
            )

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_paths = {
                item["path"] for item in manifest["artifacts"] if isinstance(item, dict)
            }
            self.assertTrue(expected_engine_artifacts <= manifest_paths)
            self.assertTrue({"semantic_ir.json", "evidence_graph.json"} <= manifest_paths)
            self.assertEqual(verify_manifest(manifest_path)["status"], "ok")

    def test_unknown_sample_stays_bounded_and_is_not_misidentified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "ordinary.bin"
            sample.write_bytes(b"MZ\x00CreateFileW\x00ordinary application\x00")
            out_dir = root / "analysis"

            result = run_engine_analyze(sample, out_dir)

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            engine = report["engine_analysis"]
            self.assertEqual(engine["status"], "ok")
            self.assertEqual(engine["engine"], "unknown")
            self.assertEqual(engine["metadata"]["status"], "unavailable")
            self.assertEqual(engine["assets"]["status"], "unavailable")
            self.assertEqual(engine["symbols"]["status"], "unavailable")
            self.assertEqual(engine["semantic_ir_fragment"]["status"], "unavailable")

    def test_missing_sample_is_a_hard_cli_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.exe"
            out_dir = root / "analysis"

            result = run_engine_analyze(missing, out_dir)

            self.assertEqual(result.returncode, 2)
            self.assertIn("sample does not exist", result.stderr)
            self.assertFalse((out_dir / "report.json").exists())
            self.assertFalse((out_dir / "engine").exists())


if __name__ == "__main__":
    unittest.main()
