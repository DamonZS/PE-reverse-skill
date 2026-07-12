import json
import shutil
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.evidence import (
    EVIDENCE_MANIFEST_SCHEMA,
    build_manifest,
    canonical_json_bytes,
    load_manifest,
    sha256_file,
    verify_manifest,
    write_manifest,
)


class EvidenceManifestTests(unittest.TestCase):
    def test_canonical_json_and_file_hash_are_stable(self) -> None:
        self.assertEqual(canonical_json_bytes({"b": 1, "a": 2}), canonical_json_bytes({"a": 2, "b": 1}))
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "evidence.bin"
            source.write_bytes(b"evidence")
            self.assertEqual(sha256_file(source), sha256_file(source))

    def test_manifest_is_portable_and_verifies_declared_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out = root / "out"
            artifact = out / "gui" / "tree.json"
            sample.write_bytes(b"MZ sample")
            artifact.parent.mkdir(parents=True)
            artifact.write_text('{"controls": 2}\n', encoding="utf-8")

            manifest = build_manifest(
                out,
                [
                    {
                        "path": artifact,
                        "kind": "runtime_tree",
                        "tool": "gui_runtime_probe",
                        "source_trace_index": 3,
                    }
                ],
                sample=sample,
                unavailable_stages=[{"tool": "frida_trace", "status": "unavailable"}],
            )
            written = write_manifest(manifest, out / "evidence-manifest.json")

            self.assertEqual(written["schema"], EVIDENCE_MANIFEST_SCHEMA)
            self.assertTrue(written["manifest_id"].startswith("sha256:"))
            self.assertEqual(written["artifacts"][0]["path"], "gui/tree.json")
            self.assertEqual(written["artifacts"][0]["size"], artifact.stat().st_size)
            self.assertEqual(written["derivations"][0]["from"], "sample")
            self.assertEqual(written["derivations"][0]["generated_by"]["tool"], "gui_runtime_probe")
            self.assertEqual(len(written["unavailable_stages"]), 1)
            self.assertEqual(verify_manifest(out / "evidence-manifest.json")["status"], "ok")

            moved = root / "moved-output"
            shutil.copytree(out, moved)
            moved_result = verify_manifest(moved / "evidence-manifest.json")
            self.assertEqual(moved_result["status"], "ok")
            self.assertEqual(moved_result["verified_file_count"], 1)

    def test_manifest_detects_missing_artifact_hash_tampering_and_id_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            artifact = out / "analysis_graph.json"
            artifact.write_bytes(b"original")
            manifest_path = out / "evidence-manifest.json"
            write_manifest(build_manifest(out, [{"path": artifact, "tool": "semantic_ir_build"}]), manifest_path)

            artifact.write_bytes(b"tampered")
            tampered = verify_manifest(manifest_path)
            self.assertEqual(tampered["status"], "failed")
            self.assertTrue(any(item["kind"] in {"hash", "size"} for item in tampered["issues"]))

            artifact.unlink()
            missing = verify_manifest(manifest_path)
            self.assertTrue(any(item["kind"] == "missing" for item in missing["issues"]))

            artifact.write_bytes(b"original")
            payload = load_manifest(manifest_path)
            payload["manifest_id"] = "sha256:" + "0" * 64
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")
            id_tampered = verify_manifest(manifest_path)
            self.assertTrue(any(item["kind"] == "manifest_id" for item in id_tampered["issues"]))

    def test_unavailable_or_missing_at_build_time_never_receives_a_fake_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            manifest = build_manifest(
                out,
                [{"path": "not-created.json", "tool": "gui_runtime_probe", "status": "unavailable"}],
            )
            artifact = manifest["artifacts"][0]
            self.assertEqual(artifact["status"], "unavailable")
            self.assertNotIn("sha256", artifact)
            self.assertEqual(verify_manifest(manifest)["status"], "ok")

    def test_duplicate_artifact_prefers_trace_tool_for_derivation_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            artifact = out / "analysis_graph.json"
            artifact.write_text("{}\n", encoding="utf-8")

            manifest = build_manifest(
                out,
                [
                    {"path": artifact, "kind": "behavior-evidence-graph"},
                    {
                        "path": artifact,
                        "kind": "behavior-evidence-graph",
                        "tool": "gui_behavior_graph",
                        "source_trace_index": 7,
                    },
                ],
            )

            self.assertEqual(len(manifest["artifacts"]), 1)
            self.assertEqual(manifest["artifacts"][0]["tool"], "gui_behavior_graph")
            self.assertEqual(manifest["artifacts"][0]["generated_by"]["tool"], "gui_behavior_graph")
            self.assertEqual(manifest["derivations"][0]["generated_by"]["tool"], "gui_behavior_graph")


if __name__ == "__main__":
    unittest.main()
