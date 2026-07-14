from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.core.capabilities.audit_contract import (
    validate_capability_audit_record,
)
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers import build_default_registry
from reverse_analyzer.providers.hook_target_resolver import HookTargetResolverProvider
from tests.test_hook_target_resolution import _fixture


ROOT = Path(__file__).resolve().parents[1]


class HookTargetCapabilityTests(unittest.TestCase):
    def _request(self, module: Path, *, session_id: str = "hook-target-test") -> CapabilityRequest:
        return CapabilityRequest(
            capability="hook_target_resolver",
            action="resolve",
            target=TargetIdentity(
                kind="module",
                path=str(module),
                sha256="fixture-module",
                display_name=module.name,
            ),
            params={
                "specification": {
                    "method": "module_rva",
                    "module_path": str(module),
                    "module_base": 0x180000000,
                    "rva": 0x1300,
                }
            },
            session_id=session_id,
            provenance={"source": "unit-test"},
        )

    def test_default_registry_exposes_resolver(self) -> None:
        registry = build_default_registry()
        self.assertIn("hook_target_resolver", registry.list_capabilities())
        self.assertEqual(
            registry.list_providers("hook_target_resolver"),
            ["deterministic_hook_target_resolver"],
        )

    def test_offline_resolution_materializes_auditable_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "fixture.dll"
            module.write_bytes(_fixture())
            out_dir = Path(temporary) / "out"
            provider = HookTargetResolverProvider()
            plan = provider.plan(self._request(module))

            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.to_dict())
            result = provider.execute(plan)
            self.assertEqual(result.status, "ok")
            self.assertEqual(result.after_snapshot["resolution"]["address"], 0x180001300)
            self.assertFalse(result.after_snapshot["target_mutated"])

            bundle = provider.collect_artifacts(result, str(out_dir))
            self.assertEqual(len(bundle.artifacts), 3)
            audit_path = out_dir / "hook-targets" / "hook-target-test" / "audit.json"
            manifest_path = out_dir / "hook-targets" / "hook-target-test" / "manifest.json"
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            contract = validate_capability_audit_record(audit)
            self.assertTrue(contract.ok, contract.errors)
            self.assertEqual(len(manifest["artifacts"]), 2)

            rollback = provider.rollback(result)
            self.assertTrue(rollback.ok)
            self.assertTrue(rollback.restored)
            self.assertEqual(result.rollback_plan["status"], "completed")

    def test_invalid_specification_fails_validation_without_resolution(self) -> None:
        provider = HookTargetResolverProvider()
        request = CapabilityRequest(
            capability="hook_target_resolver",
            action="resolve",
            target=TargetIdentity(kind="sample", display_name="invalid"),
            params={"specification": []},
            session_id="invalid-spec",
        )
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.after_snapshot["resolution"]["method"], "validation")

    def test_live_resolution_is_explicitly_dependency_gated(self) -> None:
        provider = HookTargetResolverProvider()
        request = CapabilityRequest(
            capability="hook_target_resolver",
            action="resolve_live",
            target=TargetIdentity(kind="process", pid=1, display_name="current-host"),
            params={"specification": {"target": "winsock_send"}},
            session_id="live-gate",
        )
        result = provider.execute(provider.plan(request))

        self.assertIn(result.status, {"ok", "unavailable", "failed"})
        resolution = result.after_snapshot["resolution"]
        self.assertTrue(
            str(resolution["evidence_tier"]).startswith("live")
            or resolution["evidence_tier"] == "unavailable"
        )
        if result.status == "ok":
            self.assertTrue(resolution["production_ready"])

    def test_public_cli_persists_resolution_report_manifest_and_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "fixture.dll"
            module.write_bytes(_fixture())
            out_dir = root / "out"
            specification = {
                "method": "module_rva",
                "module_path": str(module),
                "module_base": 0x180000000,
                "rva": 0x1300,
            }

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "reverse_analyzer",
                    "capability",
                    "run",
                    "--capability",
                    "hook_target_resolver",
                    "--action",
                    "resolve",
                    "--sample",
                    str(module),
                    "--out",
                    str(out_dir),
                    "--param",
                    f"specification={json.dumps(specification)}",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            command_payload = json.loads(completed.stdout)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            manifest = json.loads(
                (out_dir / "evidence-manifest.json").read_text(encoding="utf-8")
            )
            section = report["memory_analysis"]
            record = report["capability_audit"]["records"][0]
            session_id = command_payload["session_id"]
            resolution_path = out_dir / "hook-targets" / session_id / "resolution.json"
            audit_path = out_dir / "hook-targets" / session_id / "audit.json"
            provider_manifest_path = out_dir / "hook-targets" / session_id / "manifest.json"

            self.assertEqual(section["capability"], "hook_target_resolver")
            self.assertEqual(section["status"], "ok")
            self.assertEqual(section["address"], 0x180001300)
            self.assertEqual(record["dashboard_trace"][0]["kind"], "hook_target_resolution")
            self.assertTrue(validate_capability_audit_record(record).ok)
            self.assertTrue(resolution_path.is_file())
            self.assertTrue(audit_path.is_file())
            self.assertTrue(provider_manifest_path.is_file())
            manifest_paths = {
                (out_dir / item["path"]).resolve() for item in manifest["artifacts"]
            }
            self.assertIn(resolution_path.resolve(), manifest_paths)
            self.assertIn(audit_path.resolve(), manifest_paths)
            self.assertIn(provider_manifest_path.resolve(), manifest_paths)


if __name__ == "__main__":
    unittest.main()
