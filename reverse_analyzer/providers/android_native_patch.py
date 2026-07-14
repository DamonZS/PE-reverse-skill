from __future__ import annotations

from collections.abc import Mapping
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any, Optional

from reverse_analyzer.core.capabilities.models import (
    CapabilityArtifact,
    CapabilityArtifactBundle,
    CapabilityExecutionResult,
    CapabilityPlan,
    CapabilityRequest,
    CapabilityRollbackResult,
    CapabilityValidation,
)
from reverse_analyzer.tools.android_native_patch import (
    android_native_patch_apk,
    rollback_android_native_patch_apk,
    verify_android_native_patch_apk,
)
from reverse_analyzer.tools.executor import ToolResult


_SUPPORTED_ACTIONS = {"plan", "apply", "verify", "rollback"}
_PLAN_IDENTITY_KEY = "android_native_patch_plan_identity"
_RESULT_IDENTITY_KEY = "android_native_patch_result_identity"
_IDENTITY_SCHEMA_VERSION = 1
_MAX_IDENTITY_JSON_BYTES = 32 * 1024 * 1024
_APPLY_ARGUMENTS = (
    "abi",
    "library_path",
    "library",
    "lib_path",
    "virtual_address",
    "relative_virtual_address",
    "rva",
    "file_offset",
    "expected",
    "replacement",
    "instruction_mode",
    "operation_id",
    "intent",
    "sign",
    "signing",
    "apksigner",
    "apktool",
    "signing_timeout",
    "limits",
)
_APPLY_PARAMETERS = set(_APPLY_ARGUMENTS) | {
    "out_path",
    "artifact_dir",
    "out_dir",
    "rollback_out_path",
    "rollback_artifact_dir",
}
_VERIFY_PARAMETERS = {
    "plan",
    "verify_out_dir",
    "artifact_dir",
    "out_dir",
    "apksigner",
    "signing_timeout",
    "limits",
}
_ROLLBACK_PARAMETERS = {
    "rollback",
    "out_path",
    "artifact_dir",
    "out_dir",
    "original_apk",
    "apksigner",
    "signing_timeout",
    "limits",
}


class AndroidNativePatchProvider:
    """Run checked native-library APK patches through the capability lifecycle."""

    capability_name = "android_native_patch"
    provider_name = "local_android_native_patch"
    priority = 10

    def __init__(self) -> None:
        self._issued_plan_identities: dict[str, str] = {}
        self._issued_result_identities: dict[str, str] = {}

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        return (
            request.capability == self.capability_name
            and bool(request.target.path)
            and _normalize_action(request.action) in _SUPPORTED_ACTIONS
        )

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        action = _normalize_action(request.action)
        if action not in _SUPPORTED_ACTIONS:
            raise ValueError(
                f"unsupported android_native_patch action: {action or request.action!r}"
            )
        target_path = _target_path(request)
        before_snapshot = _file_snapshot(target_path)
        session_id = request.session_id or (
            f"android-native-patch-{str(before_snapshot.get('sha256') or 'session')[:12]}"
        )
        parameters = _normalize_parameters(
            request.params,
            action=action,
            target_path=target_path,
            session_id=session_id,
            context=context,
        )
        if action == "apply":
            rollback_plan = {
                "supported": False,
                "status": "pending",
                "mode": "verified_apk_copy",
                "verification_out_path": parameters["rollback_out_path"],
                "artifact_dir": parameters["rollback_artifact_dir"],
            }
        else:
            rollback_plan = {
                "supported": False,
                "status": "not_required",
                "mode": "not_required",
            }

        capability_plan = CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=action,
            parameters=parameters,
            steps=[
                {"step": "verify_apk_precondition", "status": "planned"},
                {"step": "verify_native_patch_preimage", "status": "planned"},
                {"step": f"{action}_apk_copy", "status": "planned"},
                {"step": "collect_hash_backed_artifacts", "status": "planned"},
            ],
            precondition_hash=before_snapshot.get("sha256"),
            before_snapshot=before_snapshot,
            rollback_plan=rollback_plan,
            provenance={
                **dict(request.provenance or {}),
                "provider": self.provider_name,
                "target_declared_sha256": request.target.sha256,
            },
        )
        self._issue_plan_identity(capability_plan)
        return capability_plan

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        del context
        checks: list[dict[str, Any]] = []
        warnings: list[str] = []
        errors: list[str] = []

        identity_ok, identity_errors, identity_details = self._verify_plan_identity(plan)
        checks.append(
            {
                "name": "issued_plan_identity",
                "status": "ok" if identity_ok else "failed",
                **identity_details,
            }
        )
        errors.extend(identity_errors)

        target_path = _resolved_path(getattr(plan.target, "path", None))
        current_snapshot = _file_snapshot(target_path)
        target_ok = (
            bool(current_snapshot.get("exists"))
            and _valid_sha256(plan.precondition_hash)
            and _hashes_equal(current_snapshot.get("sha256"), plan.precondition_hash)
        )
        checks.append(
            {
                "name": "target_precondition_hash",
                "status": "ok" if target_ok else "failed",
                "expected": plan.precondition_hash,
                "actual": current_snapshot.get("sha256"),
            }
        )
        if not target_ok:
            errors.append("target does not match the planned precondition hash")

        apk_path_ok = target_path is not None and target_path.suffix.casefold() == ".apk"
        checks.append(
            {
                "name": "apk_target_path",
                "status": "ok" if apk_path_ok else "failed",
                "path": str(target_path) if target_path is not None else None,
            }
        )
        if not apk_path_ok:
            errors.append("android_native_patch target must be an APK path")

        declared_hash = (
            plan.provenance.get("target_declared_sha256")
            if isinstance(plan.provenance, Mapping)
            else None
        )
        if declared_hash:
            declared_ok = _hashes_equal(declared_hash, current_snapshot.get("sha256"))
            checks.append(
                {
                    "name": "declared_target_hash",
                    "status": "ok" if declared_ok else "failed",
                    "expected": declared_hash,
                    "actual": current_snapshot.get("sha256"),
                }
            )
            if not declared_ok:
                errors.append("declared target hash differs from the current APK")

        path_checks, path_errors = _validate_plan_paths(plan)
        checks.extend(path_checks)
        errors.extend(path_errors)

        if not errors:
            try:
                tool_result, preflight_evidence = _preflight_action(plan)
                tool_ok, tool_errors, details = _verify_preflight(
                    plan,
                    tool_result,
                    preflight_evidence,
                )
            except Exception as exc:  # noqa: BLE001 - provider validation must fail closed
                tool_ok = False
                tool_errors = [f"{type(exc).__name__}: {exc}"]
                details = {"exception": type(exc).__name__}
            checks.append(
                {
                    "name": "android_native_patch_preflight",
                    "status": "ok" if tool_ok else "failed",
                    **details,
                }
            )
            errors.extend(tool_errors)
        else:
            checks.append(
                {
                    "name": "android_native_patch_preflight",
                    "status": "failed",
                    "skipped": True,
                    "reason": "plan, target, or output path validation failed",
                }
            )

        if plan.action == "plan":
            warnings.append("plan action validates in a temporary directory and creates no persistent APK")

        return CapabilityValidation(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=str(plan.session_id or ""),
            ok=not errors,
            checks=checks,
            warnings=warnings,
            errors=_dedupe(errors),
        )

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        target_path = _resolved_path(getattr(plan.target, "path", None))
        current_snapshot = _file_snapshot(target_path)
        if not _hashes_equal(current_snapshot.get("sha256"), plan.precondition_hash):
            raise RuntimeError(
                "target changed after planning or validation; refusing Android native patch execution"
            )

        validation = self.validate(plan, context=context)
        execution_errors: list[str] = []
        cleanup_paths: tuple[Path, ...] = ()
        cleanup_enabled = False
        if not validation.ok:
            tool_result = _failed_result(
                "android_native_patch_validation",
                "; ".join(validation.errors) or "Android native patch validation failed",
            )
        elif plan.action == "plan":
            _require_target_precondition(plan, target_path)
            tool_result = ToolResult(
                tool="android_native_patch_apk",
                status="planned",
                data={
                    "status": "planned",
                    "valid": True,
                    "dry_run": True,
                    "source_apk_path": str(target_path),
                    "source_sha256": plan.precondition_hash,
                    "original_apk_unchanged": True,
                    "artifacts": [],
                },
            )
        else:
            identity_ok, identity_errors, _ = self._verify_plan_identity(plan)
            if not identity_ok:
                raise RuntimeError(
                    "Android native patch plan or input changed after validation: "
                    + "; ".join(identity_errors)
                )
            with tempfile.TemporaryDirectory(
                prefix="ra-cap-android-native-execute-"
            ) as temporary:
                execution_root = Path(temporary)
                trusted_target, trusted_parameters, replacements, trusted_inputs = (
                    _trusted_execution_inputs(plan, target_path, execution_root)
                )
                owned_paths = _provider_owned_output_paths(plan)
                appeared = [
                    path
                    for path in owned_paths
                    if path.exists() or path.is_symlink()
                ]
                if appeared:
                    execution_errors.append(
                        "provider output path appeared after validation: "
                        + ", ".join(str(path) for path in appeared)
                    )
                    tool_result = _failed_result(
                        "android_native_patch_output_precondition",
                        execution_errors[-1],
                    )
                else:
                    cleanup_paths = owned_paths
                    cleanup_enabled = True
                    try:
                        tool_result = _execute_action(
                            plan,
                            target_path=trusted_target,
                            parameters=trusted_parameters,
                        )
                        tool_result = _rebind_execution_input_paths(
                            plan,
                            tool_result,
                            replacements,
                        )
                        post_identity_ok, post_identity_errors, _ = (
                            self._verify_plan_identity(plan)
                        )
                        if not post_identity_ok:
                            execution_errors.append(
                                "Android native patch plan or auxiliary input changed "
                                "during execution: "
                                + "; ".join(post_identity_errors)
                            )
                        execution_errors.extend(
                            _execution_input_errors(
                                plan,
                                target_path,
                                trusted_inputs,
                            )
                        )
                        if _effective_execution_status(
                            plan,
                            tool_result,
                            target_path,
                            execution_errors,
                        ) == "failed":
                            execution_errors.extend(
                                _cleanup_provider_owned_outputs(
                                    owned_paths,
                                    quarantine_root=execution_root / "failed-outputs",
                                )
                            )
                    except Exception:
                        _cleanup_provider_owned_outputs(
                            owned_paths,
                            quarantine_root=execution_root / "failed-outputs",
                        )
                        raise
        try:
            result = self._build_execution_result(
                plan,
                validation,
                tool_result,
                execution_errors=execution_errors,
            )
        except Exception:
            if cleanup_enabled:
                _cleanup_provider_owned_outputs(
                    cleanup_paths,
                    quarantine_root=Path(tempfile.gettempdir()) / "failed-result",
                )
            raise
        if cleanup_enabled and result.status == "failed":
            materialized = any(
                path.exists() or path.is_symlink() for path in cleanup_paths
            )
            if materialized:
                execution_errors.extend(
                    _cleanup_provider_owned_outputs(
                        cleanup_paths,
                        quarantine_root=Path(tempfile.gettempdir()) / "failed-result",
                    )
                )
                result = self._build_execution_result(
                    plan,
                    validation,
                    tool_result,
                    execution_errors=execution_errors,
                )
        return result

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        self._require_owned_result(result)
        if result.action != "apply" or not result.report_section.get("applied"):
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=result.session_id,
                ok=True,
                restored=False,
                details={"status": "not_required", "reason": "execution did not apply an APK patch"},
            )

        rollback_plan = dict(result.rollback_plan or {})
        if rollback_plan.get("status") == "completed" and result.report_section.get("restored"):
            verification = dict(result.report_section.get("rollback_verification") or {})
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=result.session_id,
                ok=True,
                restored=True,
                details={"status": "already_completed", **verification},
            )
        if not rollback_plan.get("supported") or rollback_plan.get("status") != "ready":
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=result.session_id,
                ok=False,
                restored=False,
                details={"status": "failed", "error": "rollback is not ready for this execution"},
            )

        metadata_error = _verify_lifecycle_rollback_inputs(rollback_plan)
        if metadata_error:
            return self._record_rollback_result(
                result,
                tool_result=_failed_result("android_native_patch_apk_rollback", metadata_error),
                data={},
                restored=False,
                verification_errors=[metadata_error],
            )

        patched_path = _resolved_path(rollback_plan.get("patched_path"))
        rollback_manifest = _resolved_path(rollback_plan.get("rollback_manifest"))
        restored_path = _resolved_path(rollback_plan.get("verification_out_path"))
        artifact_dir = _resolved_path(rollback_plan.get("artifact_dir"))
        assert patched_path is not None
        assert rollback_manifest is not None
        assert restored_path is not None
        assert artifact_dir is not None
        tool_result = rollback_android_native_patch_apk(
            patched_path,
            rollback=rollback_manifest,
            out_path=restored_path,
            artifact_dir=artifact_dir,
            original_apk=rollback_plan.get("source_apk_path"),
            apksigner=rollback_plan.get("apksigner"),
            signing_timeout=float(rollback_plan.get("signing_timeout") or 120.0),
            limits=rollback_plan.get("limits"),
        )
        data = _result_data(tool_result)
        verification_errors = _verify_lifecycle_rollback_materialization(
            tool_result,
            data,
            rollback_plan,
        )
        restored = not verification_errors
        return self._record_rollback_result(
            result,
            tool_result=tool_result,
            data=data,
            restored=restored,
            verification_errors=verification_errors,
        )

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        del out_dir, context
        self._require_owned_result(result)
        _require_artifact_integrity(result.artifacts)
        artifacts = list(result.artifacts or [])
        manifest_entries = list(result.evidence_manifest_entries or [])
        artifact_paths = [item.path for item in artifacts]
        manifest_paths = [str(item.get("path") or "") for item in manifest_entries]
        if len(manifest_entries) != len(artifacts) or manifest_paths != artifact_paths:
            raise ValueError("android_native_patch result artifact manifest is incomplete")
        return CapabilityArtifactBundle(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=manifest_entries,
        )

    def _issue_plan_identity(self, plan: CapabilityPlan) -> None:
        payload = _plan_identity_payload(plan)
        canonical = _canonical_json(payload)
        digest = _sha256_bytes(canonical.encode("utf-8"))
        self._issued_plan_identities[digest] = canonical
        plan.provenance[_PLAN_IDENTITY_KEY] = _plan_identity_record(payload, digest)

    def _verify_plan_identity(
        self,
        plan: CapabilityPlan,
    ) -> tuple[bool, list[str], dict[str, Any]]:
        errors: list[str] = []
        supplied = (
            plan.provenance.get(_PLAN_IDENTITY_KEY)
            if isinstance(plan.provenance, Mapping)
            else None
        )
        payload = _plan_identity_payload(plan)
        canonical = _canonical_json(payload)
        digest = _sha256_bytes(canonical.encode("utf-8"))
        expected_record = _plan_identity_record(payload, digest)
        supplied_digest = supplied.get("digest") if isinstance(supplied, Mapping) else None

        if plan.capability != self.capability_name:
            errors.append("plan capability does not belong to android_native_patch")
        if plan.provider != self.provider_name:
            errors.append("plan provider does not belong to local_android_native_patch")
        if plan.action not in _SUPPORTED_ACTIONS:
            errors.append("plan action is not supported by android_native_patch")
        if not str(plan.session_id or "").strip():
            errors.append("plan session_id must be non-empty")
        if not isinstance(supplied, Mapping):
            errors.append("android_native_patch plan identity is missing")
        elif _canonical_json(dict(supplied)) != _canonical_json(expected_record):
            errors.append("android_native_patch plan identity does not match the current plan")
        if self._issued_plan_identities.get(digest) != canonical:
            errors.append("android_native_patch plan identity was not issued by this provider instance")
        return (
            not errors,
            errors,
            {
                "expected_digest": digest,
                "actual_digest": supplied_digest,
                "input_snapshots": payload.get("input_snapshots"),
            },
        )

    def _build_execution_result(
        self,
        plan: CapabilityPlan,
        validation: CapabilityValidation,
        tool_result: ToolResult,
        *,
        execution_errors: Optional[list[str]] = None,
    ) -> CapabilityExecutionResult:
        data = _result_data(tool_result)
        target_path = _resolved_path(getattr(plan.target, "path", None))
        artifacts, artifact_errors = _tool_artifacts(data)
        artifact_errors.extend(execution_errors or [])
        status, applied, verified, restored, verification = _execution_outcome(
            plan,
            tool_result,
            data,
            target_path,
            artifact_errors,
        )
        virtual_artifact = CapabilityArtifact(
            path=(
                f"capabilities/android_native_patch/"
                f"{_safe_segment(plan.session_id)}-{plan.action}-result.json"
            ),
            kind="android-native-patch-capability-result",
            description=f"Capability result for android_native_patch:{plan.action}",
            metadata={"materialized": False},
        )
        artifacts.append(virtual_artifact)

        output_path = _result_output_path(plan, data)
        target_snapshot = _file_snapshot(target_path)
        output_snapshot = _file_snapshot(output_path)
        after_snapshot = {
            "target": target_snapshot,
            "output": output_snapshot,
            "tool_status": _normalized_status(getattr(tool_result, "status", None)),
            "effective_status": status,
            "applied": applied,
            "verified": verified,
            "restored": restored,
        }
        rollback_plan = dict(plan.rollback_plan or {})
        if plan.action == "apply":
            rollback_plan.update(
                {"supported": False, "status": "pending", "mode": "verified_apk_copy"}
            )
            if applied:
                rollback_snapshot = _file_snapshot(data.get("rollback_path"))
                rollback_plan.update(
                    {
                        "supported": True,
                        "status": "ready",
                        "patched_path": data.get("patched_apk_path"),
                        "patched_sha256": data.get("patched_sha256"),
                        "rollback_manifest": data.get("rollback_path"),
                        "rollback_manifest_sha256": rollback_snapshot.get("sha256"),
                        "source_apk_path": data.get("source_apk_path"),
                        "source_sha256": data.get("source_sha256"),
                        "verification_out_path": plan.parameters.get("rollback_out_path"),
                        "artifact_dir": plan.parameters.get("rollback_artifact_dir"),
                        "apksigner": plan.parameters.get("apksigner"),
                        "signing_timeout": plan.parameters.get("signing_timeout", 120.0),
                        "limits": plan.parameters.get("limits"),
                    }
                )

        engine_error = getattr(tool_result, "error", None)
        verification_errors = list(verification.get("errors") or [])
        error_parts = ([str(engine_error)] if engine_error else []) + verification_errors
        error = "; ".join(_dedupe(error_parts)) or None
        report_section = {
            "capability": self.capability_name,
            "provider": self.provider_name,
            "action": plan.action,
            "status": status,
            "target_path": str(target_path) if target_path is not None else None,
            "output_path": str(output_path) if output_path is not None else None,
            "source_sha256": data.get("source_sha256") or target_snapshot.get("sha256"),
            "output_sha256": output_snapshot.get("sha256"),
            "dry_run": plan.action == "plan" and status == "planned",
            "applied": applied,
            "verified": verified,
            "restored": restored,
            "preimage_verified": verification.get("preimage_verified", False),
            "engine": getattr(tool_result, "tool", None),
            "error": error,
        }
        dashboard_trace = [
            {
                "kind": "android_native_patch_execution",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "action": plan.action,
                "status": status,
                "applied": applied,
                "verified": verified,
                "restored": restored,
                "target_path": report_section["target_path"],
                "output_path": report_section["output_path"],
            }
        ]
        result = CapabilityExecutionResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=dict(plan.before_snapshot or {}),
            after_snapshot=after_snapshot,
            rollback_plan=rollback_plan,
            artifacts=artifacts,
            evidence_manifest_entries=[
                _manifest_entry(item, status=status) for item in artifacts
            ],
            report_section=report_section,
            dashboard_trace=dashboard_trace,
            provenance={
                **dict(plan.provenance or {}),
                "precondition_hash": plan.precondition_hash,
                "plan": plan.to_dict(),
                "validation": validation.to_dict(),
                "engine_result": {
                    "tool": getattr(tool_result, "tool", None),
                    "status": _normalized_status(getattr(tool_result, "status", None)),
                    "error": engine_error,
                    "verification_errors": verification_errors,
                },
            },
        )
        self._issue_result_identity(result)
        return result

    def _record_rollback_result(
        self,
        result: CapabilityExecutionResult,
        *,
        tool_result: ToolResult,
        data: Mapping[str, Any],
        restored: bool,
        verification_errors: list[str],
    ) -> CapabilityRollbackResult:
        rollback_artifacts, artifact_errors = _tool_artifacts(data)
        verification_errors = _dedupe([*verification_errors, *artifact_errors])
        restored = restored and not verification_errors
        if rollback_artifacts:
            result.artifacts.extend(rollback_artifacts)
            result.evidence_manifest_entries.extend(
                _manifest_entry(item, status="ok" if restored else "failed")
                for item in rollback_artifacts
            )

        restored_identity = _mapping(data.get("restored_apk"))
        restored_path = _resolved_path(restored_identity.get("path"))
        restored_snapshot = _file_snapshot(restored_path)
        status = "ok" if restored else "failed"
        result.rollback_plan["status"] = "completed" if restored else "failed"
        result.after_snapshot["rollback_output"] = restored_snapshot
        result.dashboard_trace.append(
            {
                "kind": "android_native_patch_rollback",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "status": status,
                "restored": restored,
                "restored_path": str(restored_path) if restored_path is not None else None,
                "restored_sha256": restored_snapshot.get("sha256"),
            }
        )
        error_parts = [str(getattr(tool_result, "error", None) or ""), *verification_errors]
        verification = {
            "status": status,
            "restored": restored,
            "restored_path": str(restored_path) if restored_path is not None else None,
            "source_sha256": result.rollback_plan.get("source_sha256"),
            "patched_sha256": result.rollback_plan.get("patched_sha256"),
            "restored_sha256": restored_snapshot.get("sha256"),
            "restoration_mode": data.get("restoration_mode"),
            "error": "; ".join(_dedupe(error_parts)) or None,
        }
        result.report_section["restored"] = restored
        result.report_section["rollback_verification"] = verification
        self._issue_result_identity(result)
        return CapabilityRollbackResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            ok=restored,
            restored=restored,
            details={**verification, "artifacts": list(data.get("artifacts") or [])},
        )

    def _issue_result_identity(self, result: CapabilityExecutionResult) -> None:
        old_identity = (
            result.provenance.get(_RESULT_IDENTITY_KEY)
            if isinstance(result.provenance, Mapping)
            else None
        )
        if isinstance(old_identity, Mapping):
            self._issued_result_identities.pop(str(old_identity.get("digest") or ""), None)
        payload = _result_identity_payload(result)
        canonical = _canonical_json(payload)
        digest = _sha256_bytes(canonical.encode("utf-8"))
        self._issued_result_identities[digest] = canonical
        result.provenance[_RESULT_IDENTITY_KEY] = {
            "schema_version": _IDENTITY_SCHEMA_VERSION,
            "capability": self.capability_name,
            "provider": self.provider_name,
            "session_id": result.session_id,
            "action": result.action,
            "plan_digest": _plan_digest_from_provenance(result.provenance),
            "digest": digest,
        }

    def _require_owned_result(self, result: CapabilityExecutionResult) -> None:
        supplied = (
            result.provenance.get(_RESULT_IDENTITY_KEY)
            if isinstance(result.provenance, Mapping)
            else None
        )
        if not isinstance(supplied, Mapping):
            raise ValueError("android_native_patch result identity is missing")
        payload = _result_identity_payload(result)
        canonical = _canonical_json(payload)
        digest = _sha256_bytes(canonical.encode("utf-8"))
        expected = {
            "schema_version": _IDENTITY_SCHEMA_VERSION,
            "capability": self.capability_name,
            "provider": self.provider_name,
            "session_id": result.session_id,
            "action": result.action,
            "plan_digest": _plan_digest_from_provenance(result.provenance),
            "digest": digest,
        }
        if result.capability != self.capability_name or result.provider != self.provider_name:
            raise ValueError("capability result does not belong to this Android native patch provider")
        if _canonical_json(dict(supplied)) != _canonical_json(expected):
            raise ValueError("android_native_patch result identity does not match the result contents")
        if self._issued_result_identities.get(digest) != canonical:
            raise ValueError("android_native_patch result identity was not issued by this provider instance")
        plan_digest = str(expected.get("plan_digest") or "")
        if plan_digest not in self._issued_plan_identities:
            raise ValueError("android_native_patch result references an unknown plan identity")


def _normalize_action(action: str) -> str:
    normalized = str(action or "").strip().lower().replace("-", "_")
    if normalized in {"dry_run", "dryrun"}:
        return "plan"
    return normalized


def _target_path(request: CapabilityRequest) -> Path:
    if not request.target.path:
        raise ValueError("android_native_patch requires an APK target")
    return Path(request.target.path).expanduser().resolve()


def _normalize_parameters(
    raw: Mapping[str, Any],
    *,
    action: str,
    target_path: Path,
    session_id: str,
    context: Optional[dict[str, Any]],
) -> dict[str, Any]:
    params = {str(key): _json_value(value) for key, value in dict(raw or {}).items()}
    allowed = (
        _APPLY_PARAMETERS
        if action in {"plan", "apply"}
        else _VERIFY_PARAMETERS
        if action == "verify"
        else _ROLLBACK_PARAMETERS
    )
    unknown = sorted(set(params) - allowed)
    if unknown:
        raise ValueError("unsupported android_native_patch parameters: " + ", ".join(unknown))

    context_root = (context or {}).get("out_dir")
    out_root = (
        Path(str(context_root)).expanduser().resolve()
        if context_root
        else target_path.parent / ".reverse-analyzer"
    )
    run_root = out_root / "android-native-patch" / _safe_segment(session_id)

    if action in {"plan", "apply"}:
        artifact_dir = _path_alias(params, "artifact_dir", "out_dir") or run_root / "artifacts"
        out_path = _resolved_path(params.get("out_path")) or (
            run_root / "patched" / f"{target_path.stem}.native-patched.apk"
        )
        rollback_out_path = _resolved_path(params.get("rollback_out_path")) or (
            run_root / "rollback" / f"{target_path.stem}.restored.apk"
        )
        rollback_artifact_dir = _resolved_path(params.get("rollback_artifact_dir")) or (
            run_root / "rollback-artifacts"
        )
        params.pop("out_dir", None)
        params.update(
            {
                "artifact_dir": str(artifact_dir),
                "out_path": str(out_path),
                "rollback_out_path": str(rollback_out_path),
                "rollback_artifact_dir": str(rollback_artifact_dir),
            }
        )
        return params

    if action == "verify":
        verify_out_dir = (
            _path_alias(params, "verify_out_dir", "artifact_dir", "out_dir")
            or run_root / "verify-artifacts"
        )
        params.pop("artifact_dir", None)
        params.pop("out_dir", None)
        params["verify_out_dir"] = str(verify_out_dir)
        return params

    artifact_dir = _path_alias(params, "artifact_dir", "out_dir") or run_root / "rollback-artifacts"
    out_path = _resolved_path(params.get("out_path")) or (
        run_root / "rollback" / f"{target_path.stem}.restored.apk"
    )
    params.pop("out_dir", None)
    params.update({"artifact_dir": str(artifact_dir), "out_path": str(out_path)})
    if params.get("original_apk") not in (None, ""):
        original = _resolved_path(params.get("original_apk"))
        params["original_apk"] = str(original) if original is not None else params["original_apk"]
    return params


def _path_alias(params: Mapping[str, Any], *names: str) -> Path | None:
    values = [
        (name, _resolved_path(params.get(name)))
        for name in names
        if params.get(name) not in (None, "")
    ]
    values = [(name, path) for name, path in values if path is not None]
    if not values:
        return None
    first_name, first = values[0]
    for name, path in values[1:]:
        if not _same_path(first, path):
            raise ValueError(f"{first_name} and {name} identify different paths")
    return first


def _validate_plan_paths(plan: CapabilityPlan) -> tuple[list[dict[str, Any]], list[str]]:
    checks: list[dict[str, Any]] = []
    errors: list[str] = []
    target = _resolved_path(getattr(plan.target, "path", None))

    if plan.action in {"plan", "apply"}:
        output = _resolved_path(plan.parameters.get("out_path"))
        artifact_dir = _resolved_path(plan.parameters.get("artifact_dir"))
        ok, reason = _new_materialization_paths(target, output, artifact_dir)
        checks.append(
            {
                "name": "patch_copy_paths",
                "status": "ok" if ok else "failed",
                "output_path": str(output) if output is not None else None,
                "artifact_dir": str(artifact_dir) if artifact_dir is not None else None,
            }
        )
        if reason:
            errors.append(reason)

        rollback_output = _resolved_path(plan.parameters.get("rollback_out_path"))
        rollback_artifacts = _resolved_path(plan.parameters.get("rollback_artifact_dir"))
        rollback_ok, rollback_reason = _new_materialization_paths(
            target,
            rollback_output,
            rollback_artifacts,
            extra_collisions=(output, artifact_dir),
        )
        checks.append(
            {
                "name": "lifecycle_rollback_paths",
                "status": "ok" if rollback_ok else "failed",
                "output_path": str(rollback_output) if rollback_output is not None else None,
                "artifact_dir": str(rollback_artifacts) if rollback_artifacts is not None else None,
            }
        )
        if rollback_reason:
            errors.append(rollback_reason)
    elif plan.action == "verify":
        input_ok = _mapping_or_existing_file(plan.parameters.get("plan"))
        checks.append(
            {
                "name": "apk_patch_plan_input",
                "status": "ok" if input_ok else "failed",
            }
        )
        if not input_ok:
            errors.append("verify action requires an APK native patch plan mapping or file")
        verify_dir = _resolved_path(plan.parameters.get("verify_out_dir"))
        verify_ok = verify_dir is not None and not verify_dir.exists() and not _paths_collide(verify_dir, target)
        checks.append(
            {
                "name": "verify_artifact_path",
                "status": "ok" if verify_ok else "failed",
                "path": str(verify_dir) if verify_dir is not None else None,
            }
        )
        if not verify_ok:
            errors.append("verify artifact directory must be a new path distinct from the target APK")
    elif plan.action == "rollback":
        input_ok = _mapping_or_existing_file(plan.parameters.get("rollback"))
        checks.append(
            {
                "name": "apk_rollback_manifest_input",
                "status": "ok" if input_ok else "failed",
            }
        )
        if not input_ok:
            errors.append("rollback action requires an APK native rollback mapping or file")
        output = _resolved_path(plan.parameters.get("out_path"))
        artifact_dir = _resolved_path(plan.parameters.get("artifact_dir"))
        ok, reason = _new_materialization_paths(target, output, artifact_dir)
        checks.append(
            {
                "name": "rollback_copy_paths",
                "status": "ok" if ok else "failed",
                "output_path": str(output) if output is not None else None,
                "artifact_dir": str(artifact_dir) if artifact_dir is not None else None,
            }
        )
        if reason:
            errors.append(reason)
    return checks, _dedupe(errors)


def _new_materialization_paths(
    source: Path | None,
    output: Path | None,
    artifact_dir: Path | None,
    *,
    extra_collisions: tuple[Path | None, ...] = (),
) -> tuple[bool, str | None]:
    if source is None or output is None or artifact_dir is None:
        return False, "output and artifact paths must be present"
    if output.exists() or artifact_dir.exists():
        return False, "output APK and artifact directory must not already exist"
    collision_candidates = (source, *extra_collisions)
    if any(item is not None and _paths_collide(output, item) for item in collision_candidates):
        return False, "output APK must be a new path distinct from all patch inputs"
    if any(item is not None and _paths_collide(artifact_dir, item) for item in collision_candidates):
        return False, "artifact directory must be distinct from all patch inputs and outputs"
    if _paths_collide(output, artifact_dir) or _is_within(output, artifact_dir):
        return False, "output APK cannot be placed inside the artifact directory"
    return True, None


def _preflight_action(plan: CapabilityPlan) -> tuple[ToolResult, dict[str, Any]]:
    target = plan.target.path or ""
    params = plan.parameters
    with tempfile.TemporaryDirectory(prefix="ra-cap-android-native-patch-") as temporary:
        root = Path(temporary)
        if plan.action in {"plan", "apply"}:
            result = android_native_patch_apk(
                target,
                out_path=root / "patched.apk",
                artifact_dir=root / "patch-artifacts",
                **_selected(params, _APPLY_ARGUMENTS),
            )
        elif plan.action == "verify":
            result = verify_android_native_patch_apk(
                target,
                plan=params.get("plan"),
                out_dir=root / "verify-artifacts",
                **_selected(params, ("apksigner", "signing_timeout", "limits")),
            )
        else:
            result = rollback_android_native_patch_apk(
                target,
                rollback=params.get("rollback"),
                out_path=root / "restored.apk",
                artifact_dir=root / "rollback-artifacts",
                **_selected(
                    params,
                    ("original_apk", "apksigner", "signing_timeout", "limits"),
                ),
            )
        data = _result_data(result)
        output_value = (
            data.get("patched_apk_path")
            if plan.action in {"plan", "apply"}
            else _mapping(data.get("restored_apk")).get("path")
            if plan.action == "rollback"
            else None
        )
        output_path = _resolved_path(output_value)
        evidence = {
            "temporary_root": str(root.resolve()),
            "target_snapshot": _file_snapshot(target),
            "output_snapshot": _file_snapshot(output_path),
            "output_within_temporary_root": bool(
                output_path is not None and _is_within(output_path, root)
            ),
        }
        return result, evidence


def _verify_preflight(
    plan: CapabilityPlan,
    tool_result: ToolResult,
    preflight_evidence: Mapping[str, Any],
) -> tuple[bool, list[str], dict[str, Any]]:
    data = _result_data(tool_result)
    errors: list[str] = []
    status = _normalized_status(getattr(tool_result, "status", None))
    target_snapshot = _file_snapshot(getattr(plan.target, "path", None))
    if not _hashes_equal(target_snapshot.get("sha256"), plan.precondition_hash):
        errors.append("target changed during Android native patch preflight")
    observed_target = _mapping(preflight_evidence.get("target_snapshot"))
    if not _hashes_equal(observed_target.get("sha256"), plan.precondition_hash):
        errors.append("Android native patch preflight target snapshot is inconsistent")
    temporary_root = _resolved_path(preflight_evidence.get("temporary_root"))
    temporary_cleaned = temporary_root is not None and not temporary_root.exists()
    if not temporary_cleaned:
        errors.append("Android native patch preflight temporary directory was not cleaned")

    preimage_verified = False
    if plan.action in {"plan", "apply"}:
        preimage_verified = bool(
            _mapping(
                _mapping(_mapping(data.get("elf")).get("evidence")).get("address_mapping")
            ).get("preimage_verified")
        )
        output = _mapping(preflight_evidence.get("output_snapshot"))
        if status not in {"ok", "dependency-gated"} or data.get("valid") is not True:
            errors.append(getattr(tool_result, "error", None) or "APK patch preflight failed")
        if data.get("original_apk_unchanged") is not True:
            errors.append("APK patch preflight did not prove that the source APK stayed unchanged")
        if not _hashes_equal(data.get("source_sha256"), plan.precondition_hash):
            errors.append("APK patch preflight source hash does not match the capability plan")
        if not preimage_verified:
            errors.append("native patch preimage bytes were not verified")
        if (
            preflight_evidence.get("output_within_temporary_root") is not True
            or not output.get("exists")
            or not _hashes_equal(output.get("sha256"), data.get("patched_sha256"))
        ):
            errors.append("APK patch preflight did not produce a hash-verified temporary copy")
    elif plan.action == "verify":
        if status not in {"ok", "dependency-gated"} or data.get("valid") is not True:
            errors.append(getattr(tool_result, "error", None) or "APK patch verification preflight failed")
        observed = _mapping(data.get("target")).get("sha256")
        if not _hashes_equal(observed, plan.precondition_hash):
            errors.append("APK verification preflight target hash is inconsistent")
    else:
        restored = _mapping(preflight_evidence.get("output_snapshot"))
        if status != "ok" or data.get("valid") is not True:
            errors.append(getattr(tool_result, "error", None) or "APK rollback preflight failed")
        if (
            preflight_evidence.get("output_within_temporary_root") is not True
            or not restored.get("exists")
            or not _hashes_equal(
                restored.get("sha256"),
                _mapping(data.get("restored_apk")).get("sha256"),
            )
        ):
            errors.append("APK rollback preflight did not produce a hash-verified temporary copy")

    return (
        not errors,
        _dedupe(errors),
        {
            "tool": getattr(tool_result, "tool", None),
            "tool_status": status,
            "preimage_verified": preimage_verified,
            "temporary_cleaned": temporary_cleaned,
            "output_snapshot": _mapping(preflight_evidence.get("output_snapshot")),
        },
    )


def _require_target_precondition(
    plan: CapabilityPlan,
    target_path: Path | None,
) -> None:
    current_snapshot = _file_snapshot(target_path)
    if not _hashes_equal(current_snapshot.get("sha256"), plan.precondition_hash):
        raise RuntimeError(
            "target changed after planning or validation; refusing Android native patch execution"
        )


def _trusted_execution_inputs(
    plan: CapabilityPlan,
    target_path: Path | None,
    execution_root: Path,
) -> tuple[Path, dict[str, Any], dict[str, str], list[dict[str, Any]]]:
    if target_path is None:
        raise RuntimeError("Android native patch target path is unavailable at execution")

    identity = (
        plan.provenance.get(_PLAN_IDENTITY_KEY)
        if isinstance(plan.provenance, Mapping)
        else None
    )
    if not isinstance(identity, Mapping):
        raise RuntimeError("Android native patch plan identity is unavailable at execution")

    parameters = copy.deepcopy(dict(plan.parameters or {}))
    if not _hashes_equal(
        _canonical_digest(parameters),
        identity.get("parameters_sha256"),
    ):
        raise RuntimeError("Android native patch parameters changed after validation")

    trusted_inputs: list[dict[str, Any]] = []
    replacements: dict[str, str] = {}
    trusted_target = execution_root / "inputs" / "target.apk"
    _copy_verified_input(
        target_path,
        trusted_target,
        expected_sha256=plan.precondition_hash,
        expected_size=_mapping(plan.before_snapshot).get("size"),
        label="target",
    )
    replacements[str(trusted_target.resolve()).casefold()] = str(target_path)
    trusted_inputs.append(
        {
            "label": "target APK",
            "original_path": target_path,
            "trusted_path": trusted_target,
            "sha256": plan.precondition_hash,
            "exists": True,
        }
    )

    input_snapshots = _mapping(identity.get("input_snapshots"))
    for key in ("plan", "rollback", "original_apk"):
        value = parameters.get(key)
        if not isinstance(value, (str, Path)):
            continue
        source = _resolved_path(value)
        expected = _mapping(input_snapshots.get(key))
        if source is None:
            raise RuntimeError(f"Android native patch {key} input path is invalid")
        if expected.get("exists") is not True:
            if key == "original_apk":
                parameters[key] = None
                trusted_inputs.append(
                    {
                        "label": key,
                        "original_path": source,
                        "trusted_path": None,
                        "sha256": None,
                        "exists": False,
                    }
                )
                continue
            raise RuntimeError(f"Android native patch {key} input changed after validation")
        suffix = source.suffix if source.suffix else ".input"
        trusted_path = execution_root / "inputs" / f"{key}{suffix}"
        _copy_verified_input(
            source,
            trusted_path,
            expected_sha256=expected.get("sha256"),
            expected_size=expected.get("size"),
            label=f"{key} input",
        )
        parameters[key] = str(trusted_path)
        replacements[str(trusted_path.resolve()).casefold()] = str(source)
        trusted_inputs.append(
            {
                "label": key,
                "original_path": source,
                "trusted_path": trusted_path,
                "sha256": expected.get("sha256"),
                "exists": True,
            }
        )
    return trusted_target, parameters, replacements, trusted_inputs


def _copy_verified_input(
    source: Path,
    destination: Path,
    *,
    expected_sha256: Any,
    expected_size: Any,
    label: str,
) -> None:
    if not _valid_sha256(expected_sha256):
        raise RuntimeError(f"Android native patch {label} hash is invalid")
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    copied_size = 0
    try:
        with source.open("rb") as reader, destination.open("xb") as writer:
            for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                writer.write(chunk)
                digest.update(chunk)
                copied_size += len(chunk)
    except (OSError, ValueError) as exc:
        destination.unlink(missing_ok=True)
        raise RuntimeError(
            f"Android native patch {label} changed or became unreadable before execution"
        ) from exc

    copied_hash = digest.hexdigest()
    copied_snapshot = _file_snapshot(destination)
    current_snapshot = _file_snapshot(source)
    size_matches = expected_size is None or copied_size == expected_size
    if (
        not size_matches
        or not _hashes_equal(copied_hash, expected_sha256)
        or not _hashes_equal(copied_snapshot.get("sha256"), expected_sha256)
        or not _hashes_equal(current_snapshot.get("sha256"), expected_sha256)
    ):
        destination.unlink(missing_ok=True)
        changed = "target changed" if label == "target" else f"{label} changed"
        raise RuntimeError(
            f"{changed} after planning or validation; refusing Android native patch execution"
        )


def _execution_input_errors(
    plan: CapabilityPlan,
    target_path: Path | None,
    trusted_inputs: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    if not _hashes_equal(
        _file_snapshot(target_path).get("sha256"),
        plan.precondition_hash,
    ):
        errors.append("source APK changed while Android native patch tool was running")
    for item in trusted_inputs:
        label = str(item.get("label") or "input")
        original = _resolved_path(item.get("original_path"))
        trusted = _resolved_path(item.get("trusted_path"))
        expected_exists = item.get("exists") is True
        if not expected_exists:
            if original is not None and (original.exists() or original.is_symlink()):
                errors.append(f"{label} input appeared while the patch tool was running")
            continue
        expected_hash = item.get("sha256")
        if trusted is None or not _hashes_equal(
            _file_snapshot(trusted).get("sha256"), expected_hash
        ):
            errors.append(f"trusted {label} snapshot changed while the patch tool was running")
        if label != "target APK" and not _hashes_equal(
            _file_snapshot(original).get("sha256"), expected_hash
        ):
            errors.append(f"{label} input changed while the patch tool was running")
    return _dedupe(errors)


def _provider_owned_output_paths(plan: CapabilityPlan) -> tuple[Path, ...]:
    values: tuple[Any, ...]
    if plan.action == "apply":
        values = (plan.parameters.get("out_path"), plan.parameters.get("artifact_dir"))
    elif plan.action == "verify":
        values = (plan.parameters.get("verify_out_dir"),)
    elif plan.action == "rollback":
        values = (plan.parameters.get("out_path"), plan.parameters.get("artifact_dir"))
    else:
        values = ()
    return tuple(path for value in values if (path := _resolved_path(value)) is not None)


def _provider_artifact_directories(plan: CapabilityPlan) -> tuple[Path, ...]:
    key = "verify_out_dir" if plan.action == "verify" else "artifact_dir"
    path = _resolved_path(plan.parameters.get(key))
    return (path,) if path is not None else ()


def _rebind_execution_input_paths(
    plan: CapabilityPlan,
    tool_result: ToolResult,
    replacements: Mapping[str, str],
) -> ToolResult:
    data = _result_data(tool_result)
    if not data or not replacements:
        return tool_result

    artifact_directories = _provider_artifact_directories(plan)
    for item in data.get("artifacts") or []:
        if not isinstance(item, Mapping):
            continue
        path = _resolved_path(item.get("path"))
        if (
            path is None
            or path.suffix.casefold() != ".json"
            or not any(_is_within(path, directory) for directory in artifact_directories)
        ):
            continue
        _rewrite_json_input_paths(path, replacements)

    rebound = _replace_trusted_paths(data, replacements)
    for item in rebound.get("artifacts") or []:
        if not isinstance(item, dict):
            continue
        snapshot = _file_snapshot(item.get("path"))
        if snapshot.get("exists"):
            item["sha256"] = snapshot.get("sha256")
            item["size"] = snapshot.get("size")
    return ToolResult(
        tool=tool_result.tool,
        status=tool_result.status,
        data=rebound,
        error=tool_result.error,
        metadata=dict(tool_result.metadata or {}),
        started_at=tool_result.started_at,
        finished_at=tool_result.finished_at,
    )


def _rewrite_json_input_paths(path: Path, replacements: Mapping[str, str]) -> None:
    payload = _read_json_mapping(path)
    if payload is None:
        return
    rebound = _replace_trusted_paths(payload, replacements)
    if rebound == payload:
        return
    encoded = (
        json.dumps(rebound, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > _MAX_IDENTITY_JSON_BYTES:
        raise RuntimeError(f"Android native patch JSON artifact is too large: {path}")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.provider-",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            handle.write(encoded)
            temporary_path = Path(handle.name)
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _replace_trusted_paths(value: Any, replacements: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        return replacements.get(value.casefold(), value)
    if isinstance(value, Mapping):
        return {
            str(key): _replace_trusted_paths(item, replacements)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_replace_trusted_paths(item, replacements) for item in value]
    return value


def _effective_execution_status(
    plan: CapabilityPlan,
    tool_result: ToolResult,
    target_path: Path | None,
    execution_errors: list[str],
) -> str:
    data = _result_data(tool_result)
    _, artifact_errors = _tool_artifacts(data)
    status, _, _, _, _ = _execution_outcome(
        plan,
        tool_result,
        data,
        target_path,
        [*artifact_errors, *execution_errors],
    )
    return status


def _cleanup_provider_owned_outputs(
    paths: tuple[Path, ...],
    *,
    quarantine_root: Path,
) -> list[str]:
    errors: list[str] = []
    ordered_paths = sorted(paths, key=lambda item: len(item.parts), reverse=True)
    quarantine_token = _sha256_bytes(str(quarantine_root).encode("utf-8"))[:12]
    for index, path in enumerate(ordered_paths):
        if not path.exists() and not path.is_symlink():
            continue
        try:
            if path.is_symlink() or path.is_file():
                path.unlink()
            else:
                shutil.rmtree(path)
            continue
        except OSError:
            pass
        try:
            quarantined = path.with_name(
                f".{path.name}.android-native-patch-failed-"
                f"{quarantine_token}-{index}"
            )
            path.replace(quarantined)
        except OSError as exc:
            errors.append(f"failed to remove provider-owned output {path}: {exc}")
        else:
            errors.append(f"provider-owned output quarantined after failure: {quarantined}")
    return errors


def _execute_action(
    plan: CapabilityPlan,
    *,
    target_path: str | Path | None = None,
    parameters: Optional[Mapping[str, Any]] = None,
) -> ToolResult:
    target = target_path if target_path is not None else plan.target.path or ""
    params = parameters if parameters is not None else plan.parameters
    if plan.action == "apply":
        return android_native_patch_apk(
            target,
            out_path=params["out_path"],
            artifact_dir=params["artifact_dir"],
            **_selected(params, _APPLY_ARGUMENTS),
        )
    if plan.action == "verify":
        return verify_android_native_patch_apk(
            target,
            plan=params.get("plan"),
            out_dir=params["verify_out_dir"],
            **_selected(params, ("apksigner", "signing_timeout", "limits")),
        )
    if plan.action == "rollback":
        return rollback_android_native_patch_apk(
            target,
            rollback=params.get("rollback"),
            out_path=params["out_path"],
            artifact_dir=params["artifact_dir"],
            **_selected(
                params,
                ("original_apk", "apksigner", "signing_timeout", "limits"),
            ),
        )
    return _failed_result("android_native_patch", f"unsupported action: {plan.action}")


def _execution_outcome(
    plan: CapabilityPlan,
    tool_result: ToolResult,
    data: Mapping[str, Any],
    target_path: Path | None,
    artifact_errors: list[str],
) -> tuple[str, bool, bool, bool, dict[str, Any]]:
    errors = list(artifact_errors)
    preimage_verified = False
    raw_status = _normalized_status(getattr(tool_result, "status", None))

    if plan.action == "plan":
        if (
            raw_status != "planned"
            or data.get("valid") is not True
            or data.get("dry_run") is not True
            or data.get("artifacts") != []
        ):
            errors.append("plan action must remain a non-materializing dry run")
        status = "planned" if not errors else "failed"
        return status, False, False, False, {
            "errors": _dedupe(errors),
            "preimage_verified": not errors,
        }

    if plan.action == "apply":
        apply_errors, preimage_verified = _verify_apply_materialization(
            plan,
            tool_result,
            data,
            target_path,
        )
        errors.extend(apply_errors)
        status = raw_status if raw_status in {"ok", "dependency-gated"} and not errors else "failed"
        return status, not errors, False, False, {
            "errors": _dedupe(errors),
            "preimage_verified": preimage_verified,
        }

    if plan.action == "verify":
        errors.extend(_verify_verify_materialization(plan, tool_result, data, target_path))
        status = raw_status if raw_status in {"ok", "dependency-gated"} and not errors else "failed"
        return status, False, not errors, False, {"errors": _dedupe(errors)}

    if plan.action == "rollback":
        errors.extend(_verify_direct_rollback_materialization(plan, tool_result, data, target_path))
        status = "ok" if raw_status == "ok" and not errors else "failed"
        return status, False, False, not errors, {"errors": _dedupe(errors)}

    errors.append(f"unsupported android_native_patch action: {plan.action}")
    return "failed", False, False, False, {"errors": _dedupe(errors)}


def _verify_apply_materialization(
    plan: CapabilityPlan,
    tool_result: ToolResult,
    data: Mapping[str, Any],
    target_path: Path | None,
) -> tuple[list[str], bool]:
    errors: list[str] = []
    raw_status = _normalized_status(getattr(tool_result, "status", None))
    expected_output = _resolved_path(plan.parameters.get("out_path"))
    actual_output = _resolved_path(data.get("patched_apk_path"))
    target_snapshot = _file_snapshot(target_path)
    output_snapshot = _file_snapshot(actual_output)
    preimage_verified = bool(
        _mapping(
            _mapping(_mapping(data.get("elf")).get("evidence")).get("address_mapping")
        ).get("preimage_verified")
    )

    if raw_status not in {"ok", "dependency-gated"} or data.get("valid") is not True:
        errors.append("Android native patch engine did not report a valid materialized APK")
    if data.get("original_apk_unchanged") is not True:
        errors.append("Android native patch engine did not prove the original APK stayed unchanged")
    if not _hashes_equal(target_snapshot.get("sha256"), plan.precondition_hash):
        errors.append("source APK changed while applying the native patch")
    if not _hashes_equal(data.get("source_sha256"), plan.precondition_hash):
        errors.append("patch engine source hash does not match the planned APK")
    if expected_output is None or actual_output is None or not _same_path(expected_output, actual_output):
        errors.append("patched APK path does not match the planned output copy")
    if not output_snapshot.get("exists") or not _hashes_equal(
        output_snapshot.get("sha256"), data.get("patched_sha256")
    ):
        errors.append("patched APK hash does not match the materialized copy")
    if not preimage_verified:
        errors.append("native patch preimage bytes were not verified")

    artifact_paths = _artifact_path_set(data)
    required = {
        "patched APK": expected_output,
        "APK patch plan": _resolved_path(data.get("plan_path")),
        "APK verification": _resolved_path(data.get("verify_path")),
        "APK rollback manifest": _resolved_path(data.get("rollback_path")),
    }
    artifact_dir = _resolved_path(plan.parameters.get("artifact_dir"))
    for label, path in required.items():
        if path is None or not path.is_file():
            errors.append(f"{label} is missing after patch execution")
        elif _path_key(path) not in artifact_paths:
            errors.append(f"{label} is missing from patch artifact metadata")
        if label != "patched APK" and path is not None and artifact_dir is not None and not _is_within(path, artifact_dir):
            errors.append(f"{label} is outside the planned artifact directory")
    return _dedupe(errors), preimage_verified


def _verify_verify_materialization(
    plan: CapabilityPlan,
    tool_result: ToolResult,
    data: Mapping[str, Any],
    target_path: Path | None,
) -> list[str]:
    errors: list[str] = []
    raw_status = _normalized_status(getattr(tool_result, "status", None))
    if raw_status not in {"ok", "dependency-gated"} or data.get("valid") is not True:
        errors.append("Android native APK verification did not pass")
    target_snapshot = _file_snapshot(target_path)
    if not _hashes_equal(target_snapshot.get("sha256"), plan.precondition_hash):
        errors.append("verified APK changed during verification")
    observed = _mapping(data.get("target")).get("sha256")
    if not _hashes_equal(observed, plan.precondition_hash):
        errors.append("verification report target hash is inconsistent")
    expected_verify = _resolved_path(
        Path(str(plan.parameters.get("verify_out_dir"))) / "native-patch-verify.json"
    )
    actual_verify = _resolved_path(data.get("verify_path"))
    if expected_verify is None or actual_verify is None or not _same_path(expected_verify, actual_verify):
        errors.append("verification artifact path does not match the capability plan")
    elif not actual_verify.is_file() or _path_key(actual_verify) not in _artifact_path_set(data):
        errors.append("verification artifact is missing or absent from artifact metadata")
    return _dedupe(errors)


def _verify_direct_rollback_materialization(
    plan: CapabilityPlan,
    tool_result: ToolResult,
    data: Mapping[str, Any],
    target_path: Path | None,
) -> list[str]:
    errors: list[str] = []
    if _normalized_status(getattr(tool_result, "status", None)) != "ok" or data.get("valid") is not True:
        errors.append("Android native APK rollback did not pass")
    target_snapshot = _file_snapshot(target_path)
    if not _hashes_equal(target_snapshot.get("sha256"), plan.precondition_hash):
        errors.append("patched APK changed while creating the rollback copy")
    expected_output = _resolved_path(plan.parameters.get("out_path"))
    restored = _mapping(data.get("restored_apk"))
    actual_output = _resolved_path(restored.get("path"))
    output_snapshot = _file_snapshot(actual_output)
    if expected_output is None or actual_output is None or not _same_path(expected_output, actual_output):
        errors.append("rollback APK path does not match the planned output copy")
    if not output_snapshot.get("exists") or not _hashes_equal(
        output_snapshot.get("sha256"), restored.get("sha256")
    ):
        errors.append("rollback APK hash does not match the materialized copy")
    if actual_output is None or _path_key(actual_output) not in _artifact_path_set(data):
        errors.append("rollback APK is missing from artifact metadata")
    return _dedupe(errors)


def _verify_lifecycle_rollback_inputs(rollback_plan: Mapping[str, Any]) -> str | None:
    patched = _resolved_path(rollback_plan.get("patched_path"))
    manifest = _resolved_path(rollback_plan.get("rollback_manifest"))
    output = _resolved_path(rollback_plan.get("verification_out_path"))
    artifacts = _resolved_path(rollback_plan.get("artifact_dir"))
    if patched is None or manifest is None or output is None or artifacts is None:
        return "rollback metadata is incomplete"
    if not _hashes_equal(_file_snapshot(patched).get("sha256"), rollback_plan.get("patched_sha256")):
        return "patched APK changed after execution; refusing rollback"
    if not _hashes_equal(
        _file_snapshot(manifest).get("sha256"), rollback_plan.get("rollback_manifest_sha256")
    ):
        return "APK rollback manifest changed after execution; refusing rollback"
    ok, reason = _new_materialization_paths(patched, output, artifacts, extra_collisions=(manifest,))
    if not ok:
        return reason
    source = _resolved_path(rollback_plan.get("source_apk_path"))
    if source is not None and source.is_file() and not _hashes_equal(
        _file_snapshot(source).get("sha256"), rollback_plan.get("source_sha256")
    ):
        return "original APK changed after patch execution; refusing exact rollback"
    return None


def _verify_lifecycle_rollback_materialization(
    tool_result: ToolResult,
    data: Mapping[str, Any],
    rollback_plan: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    if _normalized_status(getattr(tool_result, "status", None)) != "ok" or data.get("valid") is not True:
        errors.append(getattr(tool_result, "error", None) or "Android native APK rollback failed")
    expected_output = _resolved_path(rollback_plan.get("verification_out_path"))
    restored = _mapping(data.get("restored_apk"))
    actual_output = _resolved_path(restored.get("path"))
    output_snapshot = _file_snapshot(actual_output)
    if expected_output is None or actual_output is None or not _same_path(expected_output, actual_output):
        errors.append("lifecycle rollback output path does not match the planned copy")
    if not output_snapshot.get("exists") or not _hashes_equal(
        output_snapshot.get("sha256"), restored.get("sha256")
    ):
        errors.append("lifecycle rollback output hash is inconsistent")
    if not _hashes_equal(
        _file_snapshot(rollback_plan.get("patched_path")).get("sha256"),
        rollback_plan.get("patched_sha256"),
    ):
        errors.append("patched APK changed during lifecycle rollback")
    source = _resolved_path(rollback_plan.get("source_apk_path"))
    if source is not None and source.is_file() and not _hashes_equal(
        _file_snapshot(source).get("sha256"), rollback_plan.get("source_sha256")
    ):
        errors.append("original APK changed during lifecycle rollback")
    if actual_output is None or _path_key(actual_output) not in _artifact_path_set(data):
        errors.append("lifecycle rollback APK is missing from artifact metadata")
    return _dedupe(errors)


def _tool_artifacts(data: Mapping[str, Any]) -> tuple[list[CapabilityArtifact], list[str]]:
    artifacts: list[CapabilityArtifact] = []
    errors: list[str] = []
    seen: set[str] = set()
    for item in data.get("artifacts") or []:
        if not isinstance(item, Mapping) or not item.get("path"):
            errors.append("patch engine returned malformed artifact metadata")
            continue
        path = _resolved_path(item.get("path"))
        if path is None:
            errors.append("patch engine returned an invalid artifact path")
            continue
        key = _path_key(path)
        if key in seen:
            continue
        seen.add(key)
        snapshot = _file_snapshot(path)
        if not snapshot.get("exists"):
            errors.append(f"patch artifact is missing: {path}")
        if item.get("sha256") and not _hashes_equal(item.get("sha256"), snapshot.get("sha256")):
            errors.append(f"patch artifact hash metadata is inconsistent: {path}")
        if item.get("size") is not None and item.get("size") != snapshot.get("size"):
            errors.append(f"patch artifact size metadata is inconsistent: {path}")
        artifacts.append(
            CapabilityArtifact(
                path=str(path),
                kind=str(item.get("kind") or "android-native-patch-artifact"),
                description=str(item.get("name") or path.name),
                metadata={
                    "materialized": bool(snapshot.get("exists")),
                    "snapshot": snapshot,
                    "declared_sha256": item.get("sha256"),
                    "declared_size": item.get("size"),
                },
            )
        )
    return artifacts, _dedupe(errors)


def _require_artifact_integrity(artifacts: list[CapabilityArtifact]) -> None:
    for artifact in artifacts or []:
        metadata = artifact.metadata if isinstance(artifact.metadata, Mapping) else {}
        if not metadata.get("materialized"):
            continue
        expected = metadata.get("snapshot") if isinstance(metadata.get("snapshot"), Mapping) else {}
        current = _file_snapshot(artifact.path)
        if (
            not current.get("exists")
            or not _hashes_equal(current.get("sha256"), expected.get("sha256"))
            or current.get("size") != expected.get("size")
        ):
            raise ValueError(f"Android native patch artifact changed after execution: {artifact.path}")


def _manifest_entry(artifact: CapabilityArtifact, *, status: str) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "tool": "android_native_patch",
        "status": status,
        "role": "android-native-patch-evidence",
    }


def _result_output_path(plan: CapabilityPlan, data: Mapping[str, Any]) -> Path | None:
    if plan.action == "apply":
        return _resolved_path(data.get("patched_apk_path") or plan.parameters.get("out_path"))
    if plan.action == "verify":
        return _resolved_path(data.get("verify_path"))
    if plan.action == "rollback":
        return _resolved_path(
            _mapping(data.get("restored_apk")).get("path") or plan.parameters.get("out_path")
        )
    return None


def _plan_identity_payload(plan: CapabilityPlan) -> dict[str, Any]:
    provenance = dict(plan.provenance or {})
    provenance.pop(_PLAN_IDENTITY_KEY, None)
    parameters = _identity_value(plan.parameters)
    return {
        "schema_version": _IDENTITY_SCHEMA_VERSION,
        "capability": plan.capability,
        "provider": plan.provider,
        "session_id": plan.session_id,
        "action": plan.action,
        "target": _identity_value(plan.target),
        "parameters": parameters,
        "parameters_sha256": _canonical_digest(parameters),
        "input_snapshots": _parameter_input_snapshots(plan.parameters),
        "steps": _identity_value(plan.steps),
        "precondition_hash": plan.precondition_hash,
        "before_snapshot": _identity_value(plan.before_snapshot),
        "rollback_plan": _identity_value(plan.rollback_plan),
        "provenance": _identity_value(provenance),
    }


def _plan_identity_record(payload: Mapping[str, Any], digest: str) -> dict[str, Any]:
    target = payload.get("target") if isinstance(payload.get("target"), Mapping) else {}
    return {
        "schema_version": _IDENTITY_SCHEMA_VERSION,
        "capability": payload.get("capability"),
        "provider": payload.get("provider"),
        "session_id": payload.get("session_id"),
        "action": payload.get("action"),
        "target_path": target.get("path"),
        "target_sha256": payload.get("precondition_hash"),
        "parameters_sha256": payload.get("parameters_sha256"),
        "input_snapshots": payload.get("input_snapshots"),
        "digest": digest,
    }


def _result_identity_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    provenance = dict(result.provenance or {})
    provenance.pop(_RESULT_IDENTITY_KEY, None)
    return {
        "schema_version": _IDENTITY_SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "session_id": result.session_id,
        "status": result.status,
        "action": result.action,
        "target": _identity_value(result.target),
        "before_snapshot": _identity_value(result.before_snapshot),
        "after_snapshot": _identity_value(result.after_snapshot),
        "rollback_plan": _identity_value(result.rollback_plan),
        "artifacts": _identity_value(result.artifacts),
        "evidence_manifest_entries": _identity_value(result.evidence_manifest_entries),
        "report_section": _identity_value(result.report_section),
        "dashboard_trace": _identity_value(result.dashboard_trace),
        "provenance": _identity_value(provenance),
    }


def _plan_digest_from_provenance(provenance: Mapping[str, Any]) -> str | None:
    identity = provenance.get(_PLAN_IDENTITY_KEY)
    if isinstance(identity, Mapping) and identity.get("digest"):
        return str(identity["digest"])
    return None


def _parameter_input_snapshots(parameters: Mapping[str, Any]) -> dict[str, Any]:
    snapshots: dict[str, Any] = {}
    for key in ("plan", "rollback", "original_apk"):
        value = parameters.get(key)
        if value is None:
            continue
        if isinstance(value, (str, Path)):
            snapshots[key] = {"kind": "file", **_file_snapshot(value)}
        else:
            snapshots[key] = {"kind": "inline", "sha256": _canonical_digest(value)}
    return snapshots


def _selected(parameters: Mapping[str, Any], names: tuple[str, ...]) -> dict[str, Any]:
    return {
        name: parameters[name]
        for name in names
        if name in parameters and parameters[name] is not None
    }


def _artifact_path_set(data: Mapping[str, Any]) -> set[str]:
    paths: set[str] = set()
    for item in data.get("artifacts") or []:
        if isinstance(item, Mapping) and item.get("path"):
            path = _resolved_path(item.get("path"))
            if path is not None:
                paths.add(_path_key(path))
    return paths


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _mapping_or_existing_file(value: Any) -> bool:
    if isinstance(value, Mapping):
        return bool(value)
    path = _resolved_path(value)
    return path is not None and path.is_file()


def _result_data(result: Any) -> dict[str, Any]:
    return dict(result.data) if isinstance(getattr(result, "data", None), Mapping) else {}


def _failed_result(tool: str, error: str) -> ToolResult:
    return ToolResult(
        tool=tool,
        status="failed",
        error=error,
        data={"status": "failed", "valid": False, "artifacts": []},
    )


def _file_snapshot(path: str | Path | None) -> dict[str, Any]:
    candidate = _resolved_path(path)
    if candidate is None:
        return {"exists": False}
    try:
        if not candidate.is_file():
            return {"path": str(candidate), "exists": False}
        digest = hashlib.sha256()
        with candidate.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        stat = candidate.stat()
    except (OSError, ValueError):
        return {"path": str(candidate), "exists": False}
    return {
        "path": str(candidate),
        "exists": True,
        "sha256": digest.hexdigest(),
        "size": stat.st_size,
    }


def _read_json_mapping(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        if not path.is_file() or path.stat().st_size > _MAX_IDENTITY_JSON_BYTES:
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    return dict(payload) if isinstance(payload, Mapping) else None


def _paths_collide(left: Path | None, right: Path | None) -> bool:
    if left is None or right is None:
        return False
    if _same_path(left, right):
        return True
    try:
        return left.exists() and right.exists() and left.samefile(right)
    except OSError:
        return False


def _same_path(left: Path | None, right: Path | None) -> bool:
    return left is not None and right is not None and _path_key(left) == _path_key(right)


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def _path_key(path: Path) -> str:
    return str(path.resolve()).casefold()


def _resolved_path(value: Any) -> Path | None:
    if value in (None, ""):
        return None
    try:
        return Path(str(value)).expanduser().resolve()
    except (OSError, TypeError, ValueError):
        return None


def _valid_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(character in "0123456789abcdefABCDEF" for character in text)


def _hashes_equal(left: Any, right: Any) -> bool:
    return (
        _valid_sha256(left)
        and _valid_sha256(right)
        and str(left).casefold() == str(right).casefold()
    )


def _normalized_status(value: Any) -> str:
    status = str(value or "failed").strip().casefold()
    return status if status in {"ok", "planned", "dependency-gated", "failed", "unavailable"} else "failed"


def _canonical_digest(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _identity_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _identity_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, Mapping):
        return {str(key): _identity_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_identity_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_identity_value(item) for item in value]
        return sorted(normalized, key=_canonical_json)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _identity_value(to_dict())
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _json_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_segment(value: Any) -> str:
    text = "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "_"
        for character in str(value or "session")
    ).strip(".")
    return text[:120] or "session"


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


__all__ = ["AndroidNativePatchProvider"]
