import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "reverse_analyzer", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class EvidenceCliTests(unittest.TestCase):
    def test_analyze_writes_verifiable_manifest_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "analysis"
            sample.write_bytes(b"MZ\x90 evidence fixture")

            analyze = run_cli("analyze", str(sample), "--out", str(out_dir), "--max-iterations", "1")
            self.assertEqual(analyze.returncode, 0, analyze.stderr)

            manifest_path = out_dir / "evidence-manifest.json"
            self.assertTrue(manifest_path.is_file())
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            integrity = report["evidence_integrity"]
            self.assertEqual(integrity["status"], "ok")
            self.assertEqual(integrity["manifest_path"], "evidence-manifest.json")
            self.assertTrue(str(integrity["manifest_id"]).startswith("sha256:"))
            self.assertGreaterEqual(integrity["covered_file_count"], 1)

            verified = run_cli("evidence", "verify", "--manifest", str(manifest_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertTrue(json.loads(verified.stdout)["valid"])

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            covered_paths = {str(item.get("path")) for item in manifest.get("artifacts") or []}
            self.assertIn("semantic_ir.json", covered_paths)
            self.assertIn("evidence_graph.json", covered_paths)
            registered = next(item for item in manifest["artifacts"] if item.get("sha256"))
            artifact_path = out_dir / registered["path"]
            artifact_path.write_bytes(artifact_path.read_bytes() + b"tampered")

            tampered = run_cli("evidence", "verify", "--manifest", str(manifest_path))
            self.assertEqual(tampered.returncode, 2, tampered.stderr)
            payload = json.loads(tampered.stdout)
            self.assertFalse(payload["valid"])
            self.assertTrue(any(issue["kind"] in {"hash", "size"} for issue in payload["issues"]))

    def test_evidence_help_is_discoverable(self) -> None:
        for args, expected in (
            (("evidence", "--help"), "verify"),
            (("evidence", "verify", "--help"), "--manifest"),
        ):
            with self.subTest(args=args):
                result = run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)


if __name__ == "__main__":
    unittest.main()
