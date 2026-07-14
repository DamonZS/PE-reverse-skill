import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.core.capabilities import (
    CAPABILITY_AUDIT_REQUIRED_FIELDS,
    validate_capability_audit_record,
    validate_capability_audit_records,
)


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


class CapabilityAuditCliTests(unittest.TestCase):
    def test_mock_execution_is_persisted_as_skipped_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "out"
            sample.write_bytes(b"MZ mocked outcome fixture")

            completed = run_cli(
                "capability",
                "run",
                "--capability",
                "memory_runtime",
                "--action",
                "scan",
                "--sample",
                str(sample),
                "--out",
                str(out_dir),
                "--provider",
                "mock",
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            command_payload = json.loads(completed.stdout)
            session = json.loads(
                (out_dir / "sessions" / f"{command_payload['session_id']}.json").read_text(encoding="utf-8")
            )
            flow = session["flows"][0]
            tasks = {item["name"]: item for item in flow["tasks"]}
            self.assertEqual(session["status"], "skipped")
            self.assertEqual(flow["status"], "skipped")
            self.assertEqual(tasks["plan"]["status"], "succeeded")
            self.assertEqual(tasks["validate"]["status"], "succeeded")
            self.assertEqual(tasks["execute"]["status"], "skipped")
            self.assertEqual(session["metadata"]["capability_outcome"]["provider_status"], "mocked")
            self.assertEqual(session["metadata"]["capability_outcome"]["session_status"], "skipped")

    def test_provider_resolution_failure_still_persists_complete_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "out"
            sample.write_bytes(b"MZ provider resolution failure fixture")

            completed = run_cli(
                "capability",
                "run",
                "--capability",
                "memory_runtime",
                "--action",
                "scan",
                "--sample",
                str(sample),
                "--out",
                str(out_dir),
                "--provider",
                "missing-provider",
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("Preferred provider 'missing-provider' not found", completed.stderr)
            command_payload = json.loads(completed.stdout)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            manifest = json.loads((out_dir / "evidence-manifest.json").read_text(encoding="utf-8"))
            record = report["capability_audit"]["records"][0]
            validation = validate_capability_audit_record(record)
            self.assertTrue(validation.ok, validation.errors)
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["provider"], "missing-provider")
            self.assertEqual(record["report_section"]["phase"], "resolve")
            manifest_paths = {(out_dir / item["path"]).resolve() for item in manifest["artifacts"]}
            self.assertIn(
                (out_dir / "capabilities" / "memory_runtime_scan_resolve_failed.json").resolve(),
                manifest_paths,
            )

            session = json.loads(
                (out_dir / "sessions" / f"{command_payload['session_id']}.json").read_text(encoding="utf-8")
            )
            flow = session["flows"][0]
            tasks = {item["name"]: item for item in flow["tasks"]}
            self.assertEqual(session["status"], "failed")
            self.assertEqual(flow["status"], "failed")
            self.assertEqual(tasks["plan"]["status"], "failed")
            self.assertEqual(tasks["validate"]["status"], "skipped")
            self.assertEqual(tasks["execute"]["status"], "skipped")

    def test_injector_audit_is_reported_as_memory_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "payload.dll"
            out_dir = root / "out"
            sample.write_bytes(b"MZ controlled injector fixture")

            completed = run_cli(
                "capability",
                "run",
                "--capability",
                "injector",
                "--action",
                "plan",
                "--sample",
                str(sample),
                "--out",
                str(out_dir),
                "--provider",
                "mock",
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["memory_analysis"]["capability"], "injector")
            self.assertNotEqual((report.get("patch_analysis") or {}).get("capability"), "injector")

    def test_public_cli_persists_complete_correlated_audit_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "out"
            sample_bytes = b"MZ\x90\x00 capability audit fixture"
            sample.write_bytes(sample_bytes)

            completed = run_cli(
                "capability",
                "run",
                "--capability",
                "memory_runtime",
                "--action",
                "scan",
                "--sample",
                str(sample),
                "--out",
                str(out_dir),
                "--provider",
                "mock",
                "--rollback",
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            command_payload = json.loads(completed.stdout)
            report_path = out_dir / "report.json"
            audit_path = out_dir / "capabilities" / "memory_runtime_scan_audit.json"
            manifest_path = out_dir / "evidence-manifest.json"
            self.assertTrue(report_path.is_file())
            self.assertTrue(audit_path.is_file())
            self.assertTrue(manifest_path.is_file())

            report = json.loads(report_path.read_text(encoding="utf-8"))
            audit_artifact = json.loads(audit_path.read_text(encoding="utf-8"))
            record = report["capability_audit"]["records"][0]
            self.assertEqual(audit_artifact, record)
            self.assertTrue(set(CAPABILITY_AUDIT_REQUIRED_FIELDS).issubset(record))

            validation = validate_capability_audit_record(record)
            self.assertTrue(validation.ok, validation.errors)
            validation.require_valid()

            expected_hash = hashlib.sha256(sample_bytes).hexdigest()
            self.assertEqual(command_payload["session_id"], record["session_id"])
            self.assertEqual(command_payload["result"]["session_id"], record["session_id"])
            self.assertEqual(record["target_identity"]["path"], str(sample.resolve()))
            self.assertEqual(record["target_identity"]["sha256"], expected_hash)
            self.assertEqual(record["precondition_hash"], "mock-memory_runtime-scan")
            self.assertEqual(record["before_snapshot"]["action"], "scan")
            self.assertEqual(record["after_snapshot"]["action"], "scan")
            self.assertTrue(record["rollback_plan"]["supported"])
            self.assertEqual(record["provenance"]["entrypoint"], "cli.capability.run")
            self.assertEqual(record["provenance"]["plan"]["session_id"], record["session_id"])
            self.assertTrue(record["provenance"]["validation"]["ok"])
            self.assertEqual(record["report_section"]["status"], "mocked")
            self.assertEqual(record["dashboard_trace"][0]["kind"], "capability_execution")
            self.assertEqual(report["memory_analysis"]["session_id"], record["session_id"])
            self.assertEqual(report["memory_analysis"]["before_snapshot"], record["before_snapshot"])
            self.assertEqual(report["memory_analysis"]["after_snapshot"], record["after_snapshot"])
            self.assertEqual(report["memory_analysis"]["rollback_plan"], record["rollback_plan"])
            self.assertEqual(report["memory_analysis"]["report_section"], record["report_section"])
            self.assertEqual(report["memory_analysis"]["dashboard_trace"], record["dashboard_trace"])
            self.assertEqual(
                [event["kind"] for event in record["events"]],
                ["plan", "validate", "execute", "rollback"],
            )

            evidence_paths = {Path(item["path"]).resolve() for item in record["evidence_manifest_entries"]}
            self.assertTrue(evidence_paths)
            self.assertTrue(all(path.is_file() for path in evidence_paths))

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_paths = {(out_dir / item["path"]).resolve() for item in manifest["artifacts"]}
            self.assertTrue(evidence_paths.issubset(manifest_paths))
            self.assertIn(audit_path.resolve(), manifest_paths)
            self.assertEqual(report["capability_audit"]["summary"]["record_count"], 1)
            self.assertEqual(report["capability_audit"]["summary"]["manifest_reference_count"], 1)
            self.assertEqual(report["capability_audit"]["summary"]["dashboard_trace_count"], 1)

            verified = run_cli("evidence", "verify", "--manifest", str(manifest_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertTrue(json.loads(verified.stdout)["valid"])

    def test_show_audit_exposes_the_same_contract_as_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "out"
            sample.write_bytes(b"MZ audit show fixture")

            completed = run_cli(
                "capability",
                "run",
                "--capability",
                "patch_executor",
                "--action",
                "plan",
                "--sample",
                str(sample),
                "--out",
                str(out_dir),
                "--provider",
                "mock",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            shown = run_cli("capability", "show-audit", "--report", str(out_dir / "report.json"))
            self.assertEqual(shown.returncode, 0, shown.stderr)
            audit_section = json.loads(shown.stdout)
            validation = validate_capability_audit_records(audit_section["records"])
            self.assertTrue(validation.ok, validation.errors)
            self.assertEqual(audit_section["record_count"], 1)
            self.assertEqual(audit_section["records"][0]["capability"], "patch_executor")

    def test_contract_reports_missing_and_cross_field_inconsistencies(self) -> None:
        malformed = {
            "session_id": "session-a",
            "capability": "memory_runtime",
            "provider": "mock",
            "action": "scan",
            "status": "mocked",
            "target_identity": {"kind": "sample", "path": "sample.bin"},
            "precondition_hash": "expected",
            "before_snapshot": {"value": "before"},
            "after_snapshot": {"value": "after"},
            "rollback_plan": {"supported": True},
            "provenance": {
                "plan": {
                    "session_id": "session-b",
                    "capability": "memory_runtime",
                    "provider": "mock",
                    "action": "scan",
                    "precondition_hash": "different",
                },
                "validation": {
                    "session_id": "session-a",
                    "capability": "memory_runtime",
                    "provider": "mock",
                    "ok": True,
                },
            },
            "evidence_manifest_entries": [{"kind": "json"}],
            "report_section": {
                "capability": "memory_runtime",
                "provider": "other",
                "action": "scan",
                "status": "mocked",
            },
            "dashboard_trace": [{"status": "mocked"}],
            "events": [
                {"ts": "2026-01-01T00:00:00Z", "kind": "execute", "message": "done"},
                {"ts": "2026-01-01T00:00:01Z", "kind": "plan", "message": "planned"},
            ],
        }

        validation = validate_capability_audit_record(malformed)
        self.assertFalse(validation.ok)
        diagnostic = "\n".join(validation.errors)
        self.assertIn("provenance.plan.session_id does not match audit record", diagnostic)
        self.assertIn("provenance.plan.precondition_hash does not match audit record", diagnostic)
        self.assertIn("evidence_manifest_entries[0].path", diagnostic)
        self.assertIn("dashboard_trace[0].kind", diagnostic)
        self.assertIn("events missing required kinds: validate", diagnostic)
        self.assertIn("report_section.provider does not match audit record", diagnostic)
        with self.assertRaisesRegex(ValueError, "invalid capability audit record"):
            validation.require_valid()

    def test_contract_reports_every_missing_required_field(self) -> None:
        validation = validate_capability_audit_record({"capability": "memory_runtime"})
        self.assertFalse(validation.ok)
        diagnostic = "\n".join(validation.errors)
        for field_name in CAPABILITY_AUDIT_REQUIRED_FIELDS:
            self.assertIn(f"missing required field: {field_name}", diagnostic)

        collection = validate_capability_audit_records([])
        self.assertFalse(collection.ok)
        self.assertIn("records must not be empty", collection.errors)


if __name__ == "__main__":
    unittest.main()
