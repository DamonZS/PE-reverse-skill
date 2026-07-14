import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import reverse_analyzer.providers.patch_executor as patch_executor_module
from reverse_analyzer.core.audit.builder import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import CapabilityRequest, TargetIdentity
from reverse_analyzer.core.capabilities.audit_contract import validate_capability_audit_record
from reverse_analyzer.providers import PatchExecutorProvider, build_default_registry
from reverse_analyzer.tools.executor import ToolResult


ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _patch_plan(original: bytes) -> dict[str, Any]:
    return {
        "target_sha256": hashlib.sha256(original).hexdigest(),
        "operations": [
            {
                "id": "replace-nops",
                "kind": "replace_offset",
                "offset": 2,
                "expected": "9090",
                "replacement": "cccc",
            }
        ],
    }


class PatchCapabilityProviderTests(unittest.TestCase):
    def _request(
        self,
        source: Path,
        *,
        action: str,
        params: dict[str, Any],
        session_id: str,
    ) -> CapabilityRequest:
        return CapabilityRequest(
            capability="patch_executor",
            action=action,
            target=TargetIdentity(
                kind="sample",
                path=str(source),
                sha256=_sha256(source),
                display_name=source.name,
            ),
            params=params,
            session_id=session_id,
            provenance={"source": "test_patch_capability_provider"},
        )

    def test_default_registry_prefers_local_verified_patch_provider(self) -> None:
        registry = build_default_registry()

        self.assertEqual(
            registry.list_providers("patch_executor"),
            ["local_verified_patch", "mock"],
        )
        provider = registry.resolve("patch_executor")
        self.assertIsInstance(provider, PatchExecutorProvider)
        self.assertEqual(provider.provider_name, "local_verified_patch")

    def test_acceptance_runner_retains_production_provider_lifecycle_artifacts(self) -> None:
        configured = str(os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or "").strip()
        if not configured:
            return

        acceptance_root = Path(configured).expanduser().resolve()
        provider_root = acceptance_root / "patch" / "provider"
        provider_root.mkdir(parents=True, exist_ok=True)
        source = provider_root / "sample.bin"
        patched = provider_root / "patched.bin"
        original = b"MZ\x90\x90production-provider-acceptance"
        source.write_bytes(original)
        plan_path = provider_root / "input-plan.json"
        plan_path.write_text(json.dumps(_patch_plan(original)), encoding="utf-8")

        registry = build_default_registry()
        provider = registry.resolve("patch_executor")
        self.assertIsInstance(provider, PatchExecutorProvider)
        self.assertEqual(provider.provider_name, "local_verified_patch")
        request = self._request(
            source,
            action="apply",
            params={
                "plan": str(plan_path),
                "out_path": str(patched),
                "artifact_dir": str(provider_root),
            },
            session_id=str(os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_SESSION_ID") or "p2-provider"),
        )
        capability_plan = provider.plan(request)
        validation = provider.validate(capability_plan)
        self.assertTrue(validation.ok, validation.errors)
        result = provider.execute(capability_plan)
        self.assertEqual(result.status, "ok")
        self.assertEqual(source.read_bytes(), original)
        self.assertNotEqual(patched.read_bytes(), original)
        bundle = provider.collect_artifacts(result, str(provider_root))
        self.assertEqual(bundle.provider, "local_verified_patch")
        self.assertEqual(len(bundle.manifest_entries), len(bundle.artifacts))

        audit_record = CapabilityAuditBuilder().build_record(
            plan=capability_plan,
            validation=validation,
            result=result,
        )
        audit_contract = validate_capability_audit_record(audit_record)
        self.assertTrue(audit_contract.ok, audit_contract.errors)
        audit_path = provider_root / "audit.json"
        audit_path.write_text(
            json.dumps(audit_record.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok, rollback.details)
        self.assertTrue(rollback.restored)
        restored_path = Path(rollback.details["restored_path"])
        self.assertEqual(restored_path.read_bytes(), original)
        (provider_root / "provider-proof.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "passed",
                    "evidence_level": "repository-production-backend",
                    "capability": "patch_executor",
                    "provider": provider.provider_name,
                    "mock": False,
                    "lifecycle": ["plan", "validate", "execute", "collect_artifacts", "rollback"],
                    "validation_ok": validation.ok,
                    "execution_status": result.status,
                    "rollback_verified": rollback.ok and rollback.restored,
                    "source_sha256": _sha256(source),
                    "patched_sha256": _sha256(patched),
                    "restored_sha256": _sha256(restored_path),
                    "artifact_count": len(bundle.artifacts),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_plan_and_validate_actions_accept_dict_and_json_path_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            planned_output = root / "planned.bin"
            validated_output = root / "validated.bin"
            plan_artifacts = root / "plan-artifacts"
            validate_artifacts = root / "validate-artifacts"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            plan_payload = _patch_plan(original)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan_payload), encoding="utf-8")
            provider = PatchExecutorProvider()

            for action in ("plan", "validate", "apply", "rollback"):
                request = self._request(
                    source,
                    action=action,
                    params={},
                    session_id=f"supports-{action}",
                )
                self.assertTrue(provider.supports(request), action)

            plan_request = self._request(
                source,
                action="plan",
                params={
                    "plan": plan_payload,
                    "out_path": str(planned_output),
                    "artifact_dir": str(plan_artifacts),
                },
                session_id="provider-plan",
            )
            capability_plan = provider.plan(plan_request)
            self.assertEqual(capability_plan.provider, "local_verified_patch")
            self.assertEqual(capability_plan.action, "plan")
            self.assertEqual(capability_plan.precondition_hash, _sha256(source))
            self.assertEqual(capability_plan.parameters["plan"], plan_payload)

            plan_validation = provider.validate(capability_plan)
            self.assertTrue(plan_validation.ok, plan_validation.errors)
            planned = provider.execute(capability_plan)
            self.assertEqual(planned.status, "planned")
            self.assertFalse(planned_output.exists())
            self.assertFalse(plan_artifacts.exists())

            validate_request = self._request(
                source,
                action="validate",
                params={
                    "plan": str(plan_path),
                    "out_path": str(validated_output),
                    "artifact_dir": str(validate_artifacts),
                },
                session_id="provider-validate",
            )
            validate_plan = provider.plan(validate_request)
            validation = provider.validate(validate_plan)
            self.assertTrue(validation.ok, validation.errors)
            validated = provider.execute(validate_plan)

            self.assertEqual(validated.status, "ok")
            self.assertEqual(validated.action, "validate")
            self.assertEqual(source.read_bytes(), original)
            self.assertFalse(validated_output.exists())
            self.assertFalse(validate_artifacts.exists())

    def test_apply_writes_copy_and_manifests_then_provider_rollback_restores_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            patched = root / "patched.bin"
            artifact_dir = root / "patch-artifacts"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(_patch_plan(original)), encoding="utf-8")
            provider = build_default_registry().resolve("patch_executor")
            request = self._request(
                source,
                action="apply",
                params={
                    "plan": str(plan_path),
                    "out_path": str(patched),
                    "artifact_dir": str(artifact_dir),
                },
                session_id="provider-apply",
            )

            plan = provider.plan(request)
            self.assertFalse(plan.rollback_plan["supported"])
            self.assertEqual(plan.rollback_plan["status"], "pending")
            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)
            result = provider.execute(plan)

            manifest_path = artifact_dir / "patch_manifest.json"
            rollback_path = artifact_dir / "rollback.json"
            self.assertEqual(result.status, "ok")
            self.assertTrue(result.report_section["applied"])
            self.assertFalse(result.report_section["restored"])
            self.assertEqual(result.report_section["capability"], "patch_executor")
            self.assertTrue(result.rollback_plan["supported"])
            self.assertEqual(result.rollback_plan["status"], "ready")
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(patched.read_bytes(), b"MZ\xCC\xCCpayload")
            self.assertTrue(manifest_path.is_file())
            self.assertTrue(rollback_path.is_file())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["source_sha256"], _sha256(source))
            self.assertEqual(manifest["patched_sha256"], _sha256(patched))
            self.assertEqual(Path(manifest["source_path"]), source.resolve())
            self.assertEqual(Path(manifest["patched_path"]), patched.resolve())

            artifact_paths = {Path(item.path).resolve() for item in result.artifacts}
            self.assertIn(manifest_path.resolve(), artifact_paths)
            self.assertIn(rollback_path.resolve(), artifact_paths)
            bundle = provider.collect_artifacts(result, str(root / "runtime"))
            self.assertEqual(bundle.provider, "local_verified_patch")
            self.assertEqual(len(bundle.manifest_entries), len(bundle.artifacts))

            audit_record = CapabilityAuditBuilder().build_record(
                plan=plan,
                validation=validation,
                result=result,
            )
            audit_contract = validate_capability_audit_record(audit_record)
            self.assertTrue(audit_contract.ok, audit_contract.errors)

            rollback = provider.rollback(result)

            self.assertTrue(rollback.ok, rollback.details)
            self.assertTrue(rollback.restored)
            restored = Path(rollback.details["restored_path"])
            self.assertTrue(restored.is_file())
            self.assertNotEqual(restored.resolve(), source.resolve())
            self.assertNotEqual(restored.resolve(), patched.resolve())
            self.assertEqual(restored.read_bytes(), original)
            self.assertEqual(rollback.details["source_sha256"], _sha256(source))
            self.assertEqual(rollback.details["restored_sha256"], _sha256(restored))
            self.assertEqual(patched.read_bytes(), b"MZ\xCC\xCCpayload")
            self.assertTrue(result.report_section["restored"])
            self.assertEqual(result.rollback_plan["status"], "completed")
            provider.collect_artifacts(result, str(root / "after-rollback"))
            rollback_audit = CapabilityAuditBuilder().build_record(
                plan=plan,
                validation=validation,
                result=result,
            )
            rollback_contract = validate_capability_audit_record(rollback_audit)
            self.assertTrue(rollback_contract.ok, rollback_contract.errors)

    def test_direct_rollback_action_validates_and_restores_a_new_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            patched = root / "patched.bin"
            restored = root / "restored.bin"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            provider = PatchExecutorProvider()
            apply_plan = provider.plan(
                self._request(
                    source,
                    action="apply",
                    params={
                        "plan": _patch_plan(original),
                        "out_path": str(patched),
                        "artifact_dir": str(root / "apply-artifacts"),
                    },
                    session_id="direct-rollback-source",
                )
            )
            self.assertTrue(provider.validate(apply_plan).ok)
            apply_result = provider.execute(apply_plan)
            self.assertEqual(apply_result.status, "ok")

            rollback_plan = provider.plan(
                self._request(
                    patched,
                    action="rollback",
                    params={
                        "rollback": apply_result.rollback_plan["rollback_manifest"],
                        "out_path": str(restored),
                        "artifact_dir": str(root / "rollback-artifacts"),
                    },
                    session_id="direct-rollback",
                )
            )
            validation = provider.validate(rollback_plan)
            self.assertTrue(validation.ok, validation.errors)

            result = provider.execute(rollback_plan)

            self.assertEqual(result.status, "ok", result.report_section.get("error"))
            self.assertFalse(result.report_section["applied"])
            self.assertTrue(result.report_section["restored"])
            self.assertEqual(restored.read_bytes(), original)
            self.assertEqual(result.report_section["output_sha256"], _sha256(restored))

    def test_nested_plan_tampering_after_validation_is_rejected_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            output = root / "patched.bin"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            provider = PatchExecutorProvider()
            capability_plan = provider.plan(
                self._request(
                    source,
                    action="apply",
                    params={
                        "plan": _patch_plan(original),
                        "out_path": str(output),
                        "artifact_dir": str(root / "artifacts"),
                    },
                    session_id="nested-tamper",
                )
            )
            self.assertTrue(provider.validate(capability_plan).ok)
            capability_plan.parameters["plan"]["operations"][0]["replacement"] = "9090"

            result = provider.execute(capability_plan)

            self.assertEqual(result.status, "failed")
            self.assertIn("plan identity", result.report_section["error"])
            self.assertFalse(result.report_section["applied"])
            self.assertFalse(output.exists())
            self.assertFalse((root / "artifacts").exists())

    def test_plan_json_replacement_after_validation_is_rejected_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            output = root / "patched.bin"
            plan_path = root / "plan.json"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            plan_path.write_text(json.dumps(_patch_plan(original)), encoding="utf-8")
            provider = PatchExecutorProvider()
            capability_plan = provider.plan(
                self._request(
                    source,
                    action="apply",
                    params={
                        "plan": str(plan_path),
                        "out_path": str(output),
                        "artifact_dir": str(root / "artifacts"),
                    },
                    session_id="json-tamper",
                )
            )
            self.assertTrue(provider.validate(capability_plan).ok)
            replacement_plan = _patch_plan(original)
            replacement_plan["operations"][0]["replacement"] = "9090"
            plan_path.write_text(json.dumps(replacement_plan), encoding="utf-8")

            result = provider.execute(capability_plan)

            self.assertEqual(result.status, "failed")
            self.assertIn("plan identity", result.report_section["error"])
            self.assertFalse(output.exists())

    def test_mutated_parameters_and_recomputed_provenance_digest_are_not_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            output = root / "patched.bin"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            provider = PatchExecutorProvider()
            capability_plan = provider.plan(
                self._request(
                    source,
                    action="apply",
                    params={
                        "plan": _patch_plan(original),
                        "out_path": str(output),
                        "artifact_dir": str(root / "artifacts"),
                    },
                    session_id="forged-digest",
                )
            )
            capability_plan.parameters["plan"]["operations"][0]["replacement"] = "9090"
            identity_payload = patch_executor_module._plan_identity_payload(capability_plan)
            canonical = patch_executor_module._canonical_json(identity_payload)
            forged_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            capability_plan.provenance["patch_executor_plan_identity"] = (
                patch_executor_module._plan_identity_record(identity_payload, forged_digest)
            )

            validation = provider.validate(capability_plan)
            result = provider.execute(capability_plan)

            self.assertFalse(validation.ok)
            self.assertIn("not issued", " ".join(validation.errors))
            self.assertEqual(result.status, "failed")
            self.assertFalse(output.exists())

    def test_pe_validation_unavailable_propagates_without_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            output = root / "patched.bin"
            artifact_dir = root / "artifacts"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            patch_plan = _patch_plan(original)
            patch_plan["operations"][0]["role"] = "iat_thunk"
            provider = PatchExecutorProvider()
            capability_plan = provider.plan(
                self._request(
                    source,
                    action="apply",
                    params={
                        "plan": patch_plan,
                        "out_path": str(output),
                        "artifact_dir": str(artifact_dir),
                    },
                    session_id="pe-unavailable",
                )
            )
            unavailable = ToolResult(
                tool="validate_pe_patch_plan",
                status="unavailable",
                error="disassembly backend unavailable",
                data={"status": "unavailable", "valid": False, "artifacts": []},
            )

            with patch(
                "reverse_analyzer.patch.planner.validate_pe_patch_plan",
                return_value=unavailable,
            ):
                validation = provider.validate(capability_plan)
                result = provider.execute(capability_plan)

            self.assertFalse(validation.ok)
            checks = {item["name"]: item["status"] for item in validation.checks}
            self.assertEqual(checks["patch_engine_validation"], "unavailable")
            self.assertEqual(result.status, "unavailable")
            self.assertFalse(result.report_section["applied"])
            self.assertFalse(output.exists())
            self.assertFalse(artifact_dir.exists())

    def test_apply_never_promotes_a_planned_dry_run_to_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            output = root / "patched.bin"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            provider = PatchExecutorProvider()
            capability_plan = provider.plan(
                self._request(
                    source,
                    action="apply",
                    params={
                        "plan": _patch_plan(original),
                        "out_path": str(output),
                        "artifact_dir": str(root / "artifacts"),
                    },
                    session_id="planned-is-not-applied",
                )
            )
            self.assertTrue(provider.validate(capability_plan).ok)
            dry_run = ToolResult(
                tool="binary_patch_apply",
                status="planned",
                data={
                    "status": "planned",
                    "dry_run": True,
                    "patched_path": str(output),
                    "source_sha256": _sha256(source),
                    "artifacts": [],
                },
            )

            with patch.object(patch_executor_module, "_execute_action", return_value=dry_run):
                result = provider.execute(capability_plan)

            self.assertEqual(result.status, "failed")
            self.assertFalse(result.report_section["applied"])
            self.assertFalse(result.rollback_plan["supported"])
            self.assertEqual(result.rollback_plan["status"], "pending")
            self.assertFalse(output.exists())

    def test_rollback_rejects_a_changed_manifest_and_result_ownership_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            output = root / "patched.bin"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            provider = PatchExecutorProvider()
            capability_plan = provider.plan(
                self._request(
                    source,
                    action="apply",
                    params={
                        "plan": _patch_plan(original),
                        "out_path": str(output),
                        "artifact_dir": str(root / "artifacts"),
                    },
                    session_id="ownership",
                )
            )
            self.assertTrue(provider.validate(capability_plan).ok)
            result = provider.execute(capability_plan)
            self.assertEqual(result.status, "ok")

            for field, value in (
                ("capability", "memory_runtime"),
                ("provider", "foreign_provider"),
                ("session_id", "foreign-session"),
            ):
                with self.subTest(field=field):
                    forged = copy.deepcopy(result)
                    setattr(forged, field, value)
                    with self.assertRaisesRegex(ValueError, "result"):
                        provider.collect_artifacts(forged, str(root / "collected"))
                    with self.assertRaisesRegex(ValueError, "result"):
                        provider.rollback(forged)

            with self.assertRaisesRegex(ValueError, "provider instance"):
                PatchExecutorProvider().collect_artifacts(result, str(root / "foreign-instance"))

            rollback_path = Path(result.rollback_plan["rollback_manifest"])
            rollback_payload = json.loads(rollback_path.read_text(encoding="utf-8"))
            rollback_payload["operations"][0]["original_hex"] = "ffff"
            rollback_path.write_text(json.dumps(rollback_payload), encoding="utf-8")

            rollback = provider.rollback(result)

            self.assertFalse(rollback.ok)
            self.assertFalse(rollback.restored)
            self.assertIn("manifest changed", rollback.details["error"])
            self.assertFalse(Path(capability_plan.rollback_plan["verification_out_path"]).exists())

    def test_invalid_preimage_fails_provider_validation_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            patched = root / "patched.bin"
            artifact_dir = root / "patch-artifacts"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            invalid_plan = _patch_plan(original)
            invalid_plan["operations"][0]["expected"] = "ffff"
            provider = PatchExecutorProvider()
            request = self._request(
                source,
                action="apply",
                params={
                    "plan": invalid_plan,
                    "out_path": str(patched),
                    "artifact_dir": str(artifact_dir),
                },
                session_id="invalid-preimage",
            )

            validation = provider.validate(provider.plan(request))

            self.assertFalse(validation.ok)
            self.assertTrue(
                any("expected bytes do not match" in error for error in validation.errors),
                validation.errors,
            )
            checks = {item["name"]: item["status"] for item in validation.checks}
            self.assertEqual(checks["patch_engine_validation"], "failed")
            self.assertEqual(source.read_bytes(), original)
            self.assertFalse(patched.exists())
            self.assertFalse(artifact_dir.exists())

    def test_plan_and_validate_ignore_existing_output_but_apply_rejects_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            existing_output = root / "existing.bin"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            existing_output.write_bytes(b"do-not-overwrite")
            provider = PatchExecutorProvider()

            for action in ("plan", "validate"):
                with self.subTest(action=action):
                    request = self._request(
                        source,
                        action=action,
                        params={
                            "plan": _patch_plan(original),
                            "out_path": str(existing_output),
                            "artifact_dir": str(root / f"{action}-artifacts"),
                        },
                        session_id=f"existing-output-{action}",
                    )
                    capability_plan = provider.plan(request)
                    validation = provider.validate(capability_plan)
                    self.assertTrue(validation.ok, validation.errors)
                    self.assertNotIn("copy_output_path", {item["name"] for item in validation.checks})

            apply_request = self._request(
                source,
                action="apply",
                params={
                    "plan": _patch_plan(original),
                    "out_path": str(existing_output),
                    "artifact_dir": str(root / "apply-artifacts"),
                },
                session_id="existing-output-apply",
            )
            apply_validation = provider.validate(provider.plan(apply_request))

            self.assertFalse(apply_validation.ok)
            self.assertIn("output path must be a new path", " ".join(apply_validation.errors))
            self.assertEqual(existing_output.read_bytes(), b"do-not-overwrite")

    def test_missing_plan_hash_and_missing_precondition_hash_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            output = root / "patched.bin"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            provider = PatchExecutorProvider()
            request = self._request(
                source,
                action="apply",
                params={
                    "plan": {"operations": _patch_plan(original)["operations"]},
                    "out_path": str(output),
                    "artifact_dir": str(root / "artifacts"),
                },
                session_id="missing-plan-hash",
            )
            capability_plan = provider.plan(request)

            validation = provider.validate(capability_plan)
            self.assertFalse(validation.ok)
            self.assertIn("target_sha256 is required", " ".join(validation.errors))
            result = provider.execute(capability_plan)
            self.assertEqual(result.status, "failed")
            self.assertFalse(output.exists())

            capability_plan.precondition_hash = None
            precondition_validation = provider.validate(capability_plan)
            self.assertFalse(precondition_validation.ok)
            self.assertIn("planned precondition hash", " ".join(precondition_validation.errors))
            with self.assertRaisesRegex(RuntimeError, "target changed after validation"):
                provider.execute(capability_plan)

    def test_cli_capability_apply_writes_report_audit_and_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.bin"
            patched = root / "patched.bin"
            out_dir = root / "out"
            patch_artifacts = out_dir / "patch-engine"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(_patch_plan(original)), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "reverse_analyzer",
                    "capability",
                    "run",
                    "--capability",
                    "patch_executor",
                    "--action",
                    "apply",
                    "--sample",
                    str(source),
                    "--out",
                    str(out_dir),
                    "--param",
                    f"plan={plan_path}",
                    "--param",
                    f"out_path={patched}",
                    "--param",
                    f"artifact_dir={patch_artifacts}",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=60,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            report_path = out_dir / "report.json"
            audit_path = out_dir / "capabilities" / "patch_executor_apply_audit.json"
            evidence_manifest_path = out_dir / "evidence-manifest.json"
            patch_manifest_path = patch_artifacts / "patch_manifest.json"
            rollback_path = patch_artifacts / "rollback.json"

            self.assertEqual(payload["provider"], "local_verified_patch")
            self.assertEqual(payload["result"]["status"], "ok")
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(patched.read_bytes(), b"MZ\xCC\xCCpayload")
            for path in (
                report_path,
                out_dir / "report.md",
                audit_path,
                evidence_manifest_path,
                patch_manifest_path,
                rollback_path,
            ):
                self.assertTrue(path.is_file(), path)

            report = json.loads(report_path.read_text(encoding="utf-8"))
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            self.assertEqual(report["patch_analysis"]["provider"], "local_verified_patch")
            self.assertEqual(report["patch_analysis"]["status"], "ok")
            self.assertEqual(audit["provider"], "local_verified_patch")
            self.assertIn(
                "patch_manifest.json",
                evidence_manifest_path.read_text(encoding="utf-8"),
            )
            payload_artifacts = {Path(path).resolve() for path in payload["artifacts"]}
            self.assertIn(report_path.resolve(), payload_artifacts)
            self.assertIn(audit_path.resolve(), payload_artifacts)
            self.assertIn(patch_manifest_path.resolve(), payload_artifacts)
            self.assertIn(rollback_path.resolve(), payload_artifacts)


if __name__ == "__main__":
    unittest.main()
