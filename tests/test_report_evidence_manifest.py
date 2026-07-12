import json
import unittest
from types import SimpleNamespace

from reverse_analyzer.report import ReportBuilder


class ReportEvidenceManifestTests(unittest.TestCase):
    def test_evidence_integrity_is_in_json_and_markdown(self):
        session = SimpleNamespace(
            session_id="evidence-session",
            target="sample.exe",
            status="succeeded",
            artifacts=[],
            metadata={
                "evidence_integrity": {
                    "manifest_path": "artifacts/evidence/manifest.json",
                    "manifest_id": "manifest-20260712",
                    "covered_file_count": 3,
                    "unavailable_stage_count": 1,
                    "status": "partial",
                    "verification_command": "verify-manifest artifacts/evidence/manifest.json",
                }
            },
        )

        builder = ReportBuilder(session)
        report = json.loads(builder.to_json())
        markdown = builder.to_markdown()

        self.assertEqual(
            report["evidence_integrity"],
            {
                "manifest_path": "artifacts/evidence/manifest.json",
                "manifest_id": "manifest-20260712",
                "hash_algorithm": "sha256",
                "covered_file_count": 3,
                "unavailable_stage_count": 1,
                "status": "partial",
                "verification_command": "verify-manifest artifacts/evidence/manifest.json",
            },
        )
        self.assertIn("## Evidence Integrity", markdown)
        self.assertIn("artifacts/evidence/manifest.json", markdown)
        self.assertIn("manifest-20260712", markdown)
        self.assertIn("**Hash Algorithm:** sha256", markdown)
        self.assertIn("**Covered Files:** 3", markdown)
        self.assertIn("**Unavailable Stages:** 1", markdown)
        self.assertIn("verify-manifest artifacts/evidence/manifest.json", markdown)

    def test_missing_evidence_integrity_metadata_is_compatible(self):
        session = SimpleNamespace(
            session_id="no-evidence-session",
            target="sample.exe",
            status="succeeded",
            artifacts=[],
        )

        builder = ReportBuilder(session)
        report = json.loads(builder.to_json())
        markdown = builder.to_markdown()

        self.assertEqual(report["evidence_integrity"], {})
        self.assertIn("## Evidence Integrity", markdown)
        self.assertIn("No evidence manifest metadata recorded.", markdown)
