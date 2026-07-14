from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
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
from reverse_analyzer.providers.mock import MockCapabilityProvider
from reverse_analyzer.tools.executor import ToolResult
from reverse_analyzer.tools.patch import (
    binary_patch_apply_plan,
    binary_patch_rollback_plan,
    validate_patch_plan,
)


_SUPPORTED_ACTIONS = {"plan", "validate", "apply", "rollback"}
_PLAN_IDENTITY_KEY = "patch_executor_plan_identity"
_RESULT_IDENTITY_KEY = "patch_executor_result_identity"
_IDENTITY_SCHEMA_VERSION = 1
_MAX_IDENTITY_JSON_BYTES = 4 * 1024 * 1024


class PatchExecutorProvider:
    """Execute verified file-copy patches through the capability lifecycle."""

    capability_name = "patch_executor"
    provider_name = "local_verified_patch"
    priority = 10

    def __init__(self) -> None:
        self._issued_plan_identities: dict[str, str] = {}
        self._issued_result_identities: dict[str, str] = {}

    def supports(self, request: CapabilityRequest, context: Optional[dict[str, Any]] = None) -> bool:
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
            raise ValueError(f"unsupported patch_executor action: {action or request.action!r}")
        target_path = _target_path(request)
        session_id = request.session_id or "patch-executor-session"
        parameters = _normalize_parameters(
            request.params,
            action=action,
            target_path=target_path,
            session_id=session_id,
            context=context,
        )
        before_snapshot = _file_snapshot(target_path)
        if action == "apply":
            rollback_plan = {
                "supported": False,
                "status": "pending",
                "mode": "restored_copy",
                "verification_out_path": parameters["rollback_out_path"],
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
                {"step": "verify_target_identity", "status": "planned"},
                {"step": "validate_patch_inputs", "status": "planned"},
                {"step": f"{action}_verified_copy", "status": "planned"},
                {"step": "collect_patch_evidence", "status": "planned"},
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
        expected_hash = str(plan.precondition_hash or "")
        target_identity_ok = (
            bool(current_snapshot.get("exists"))
            and _valid_sha256(expected_hash)
            and _hashes_equal(current_snapshot.get("sha256"), expected_hash)
        )
        checks.append(
            {
                "name": "target_precondition_hash",
                "status": "ok" if target_identity_ok else "failed",
                "expected": plan.precondition_hash,
                "actual": current_snapshot.get("sha256"),
            }
        )
        if not target_identity_ok:
            errors.append("target does not match the planned precondition hash")

        declared_hash = plan.provenance.get("target_declared_sha256") if isinstance(plan.provenance, Mapping) else None
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
                errors.append("target identity hash differs from the current file")

        if plan.action in {"apply", "rollback"}:
            output_path = _resolved_path(plan.parameters.get("out_path"))
            output_ok = (
                output_path is not None
                and target_path is not None
                and not _paths_collide(output_path, target_path)
                and not output_path.exists()
            )
            checks.append(
                {
                    "name": "copy_output_path",
                    "status": "ok" if output_ok else "failed",
                    "path": str(output_path) if output_path is not None else None,
                }
            )
            if not output_ok:
                errors.append("output path must be a new path different from the target")

        if plan.action == "apply":
            output_path = _resolved_path(plan.parameters.get("out_path"))
            rollback_output = _resolved_path(plan.parameters.get("rollback_out_path"))
            rollback_output_ok = (
                rollback_output is not None
                and target_path is not None
                and output_path is not None
                and not rollback_output.exists()
                and not _paths_collide(rollback_output, target_path)
                and not _paths_collide(rollback_output, output_path)
            )
            checks.append(
                {
                    "name": "rollback_output_path",
                    "status": "ok" if rollback_output_ok else "failed",
                    "path": str(rollback_output) if rollback_output is not None else None,
                }
            )
            if not rollback_output_ok:
                errors.append("rollback output path must be new and distinct from target and patched output")

        if identity_ok and target_identity_ok:
            tool_result = _validate_action(plan)
            tool_data = _result_data(tool_result)
            tool_status = _normalized_status(getattr(tool_result, "status", None))
            tool_ok = _validation_tool_ok(plan.action, tool_status, tool_data)
            check_status = "ok" if tool_ok else tool_status if tool_status == "unavailable" else "failed"
            checks.append(
                {
                    "name": "patch_engine_validation",
                    "status": check_status,
                    "tool_status": tool_status,
                    "tool": getattr(tool_result, "tool", None),
                    "details": tool_data,
                }
            )
            if not tool_ok:
                errors.append(getattr(tool_result, "error", None) or "patch engine validation failed")
        else:
            checks.append(
                {
                    "name": "patch_engine_validation",
                    "status": "failed",
                    "details": {"skipped": True, "reason": "plan or target identity validation failed"},
                }
            )

        if plan.action in {"plan", "validate"}:
            warnings.append(f"{plan.action} action does not create a patched file")

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
            raise RuntimeError("target changed after validation; refusing patch execution")

        validation = self.validate(plan, context=context)
        if not validation.ok:
            status = _validation_failure_status(validation)
            tool_result = _failed_result(
                "patch_executor_validation",
                "; ".join(validation.errors) or "patch executor validation failed",
                status=status,
            )
        else:
            tool_result = _execute_action(plan)
        return self._build_execution_result(plan, validation, tool_result)

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        self._require_owned_result(result)
        if result.action != "apply" or result.status != "ok" or not result.report_section.get("applied"):
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=result.session_id,
                ok=True,
                restored=False,
                details={"status": "not_required", "reason": "execution did not apply a patch"},
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

        patched_path = _resolved_path(rollback_plan.get("patched_path"))
        rollback_manifest = _resolved_path(rollback_plan.get("rollback_manifest"))
        restored_path = _resolved_path(rollback_plan.get("verification_out_path"))
        metadata_error = _verify_rollback_inputs(
            patched_path,
            rollback_manifest,
            restored_path,
            rollback_plan,
        )
        if metadata_error:
            return self._record_rollback_result(
                result,
                tool_result=_failed_result("binary_patch_rollback", metadata_error),
                data={},
                restored=False,
            )

        assert patched_path is not None
        assert rollback_manifest is not None
        assert restored_path is not None
        artifact_dir = restored_path.parent / "artifacts"
        tool_result = binary_patch_rollback_plan(
            patched_path,
            rollback=rollback_manifest,
            out_path=restored_path,
            apply=True,
            artifact_dir=artifact_dir,
        )
        data = _result_data(tool_result)
        errors, restored_snapshot = _verify_rollback_materialization(
            tool_result,
            data,
            expected_restored_path=restored_path,
            expected_source_sha256=rollback_plan.get("source_sha256"),
            expected_patched_sha256=rollback_plan.get("patched_sha256"),
        )
        restored = not errors
        if errors:
            tool_result = ToolResult(
                tool=getattr(tool_result, "tool", "binary_patch_rollback"),
                status="failed",
                error="; ".join(errors),
                data=data,
            )
        if restored_snapshot:
            data = {**data, "verified_restored_snapshot": restored_snapshot}
        return self._record_rollback_result(result, tool_result=tool_result, data=data, restored=restored)

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        del out_dir, context
        self._require_owned_result(result)
        _require_artifact_integrity(result.artifacts)
        if len(result.evidence_manifest_entries or []) != len(result.artifacts or []):
            raise ValueError("patch_executor result artifact manifest is incomplete")
        return CapabilityArtifactBundle(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            artifacts=list(result.artifacts or []),
            manifest_entries=list(result.evidence_manifest_entries or []),
        )

    def _issue_plan_identity(self, plan: CapabilityPlan) -> None:
        payload = _plan_identity_payload(plan)
        canonical = _canonical_json(payload)
        digest = _sha256_bytes(canonical.encode("utf-8"))
        self._issued_plan_identities[digest] = canonical
        plan.provenance[_PLAN_IDENTITY_KEY] = _plan_identity_record(payload, digest)

    def _verify_plan_identity(self, plan: CapabilityPlan) -> tuple[bool, list[str], dict[str, Any]]:
        errors: list[str] = []
        supplied = plan.provenance.get(_PLAN_IDENTITY_KEY) if isinstance(plan.provenance, Mapping) else None
        payload = _plan_identity_payload(plan)
        canonical = _canonical_json(payload)
        calculated_digest = _sha256_bytes(canonical.encode("utf-8"))
        expected_record = _plan_identity_record(payload, calculated_digest)
        supplied_digest = supplied.get("digest") if isinstance(supplied, Mapping) else None

        if plan.capability != self.capability_name:
            errors.append("plan capability does not belong to patch_executor")
        if plan.provider != self.provider_name:
            errors.append("plan provider does not belong to local_verified_patch")
        if plan.action not in _SUPPORTED_ACTIONS:
            errors.append("plan action is not supported by patch_executor")
        if not str(plan.session_id or "").strip():
            errors.append("plan session_id must be non-empty")
        if not isinstance(supplied, Mapping):
            errors.append("plan identity is missing")
        elif _canonical_json(dict(supplied)) != _canonical_json(expected_record):
            errors.append("plan identity does not match the current nested plan contents")
        issued = self._issued_plan_identities.get(calculated_digest)
        if issued != canonical:
            errors.append("plan identity was not issued by this provider instance")
        return (
            not errors,
            errors,
            {
                "expected_digest": calculated_digest,
                "actual_digest": supplied_digest,
                "input_snapshots": payload.get("input_snapshots"),
            },
        )

    def _build_execution_result(
        self,
        plan: CapabilityPlan,
        validation: CapabilityValidation,
        tool_result: ToolResult,
    ) -> CapabilityExecutionResult:
        target_path = _resolved_path(getattr(plan.target, "path", None))
        data = _result_data(tool_result)
        status, applied, restored, verification = _execution_outcome(plan, tool_result, target_path)
        artifacts = _tool_artifacts(data)
        artifacts.append(
            CapabilityArtifact(
                path=f"patch/{plan.session_id}/capability-result.json",
                kind="patch-capability-result",
                description=f"Capability result for patch_executor:{plan.action}",
                metadata={"materialized": False},
            )
        )

        target_snapshot = _file_snapshot(target_path)
        output_path = data.get("patched_path") or data.get("restored_path")
        output_snapshot = _file_snapshot(output_path)
        after_snapshot = {
            "target": target_snapshot,
            "output": output_snapshot,
            "tool_status": _normalized_status(getattr(tool_result, "status", None)),
            "effective_status": status,
            "operation_count": len(data.get("operations") or []),
            "applied": applied,
            "restored": restored,
        }
        rollback_plan = dict(plan.rollback_plan or {})
        if plan.action == "apply":
            rollback_plan.update({"supported": False, "status": "pending", "mode": "restored_copy"})
            if applied:
                rollback_snapshot = dict(verification.get("rollback_manifest_snapshot") or {})
                rollback_plan.update(
                    {
                        "supported": True,
                        "status": "ready",
                        "patched_path": data.get("patched_path"),
                        "rollback_manifest": data.get("rollback_path"),
                        "rollback_manifest_sha256": rollback_snapshot.get("sha256"),
                        "source_sha256": data.get("source_sha256"),
                        "patched_sha256": data.get("patched_sha256"),
                    }
                )

        verification_errors = list(verification.get("errors") or [])
        engine_error = getattr(tool_result, "error", None)
        error_parts = ([str(engine_error)] if engine_error else []) + verification_errors
        error = "; ".join(_dedupe(error_parts)) or None
        report_section = {
            "capability": self.capability_name,
            "status": status,
            "provider": self.provider_name,
            "action": plan.action,
            "target_format": _target_format(target_path),
            "strategy": data.get("strategy") or "inline_patch",
            "target_path": str(target_path) if target_path is not None else None,
            "output_path": output_path,
            "source_sha256": data.get("source_sha256") or target_snapshot.get("sha256"),
            "output_sha256": (
                data.get("restored_sha256")
                if plan.action == "rollback"
                else data.get("patched_sha256")
            ),
            "operation_count": len(data.get("operations") or []),
            "dry_run": bool(data.get("dry_run", False)),
            "applied": applied,
            "restored": restored,
            "engine": getattr(tool_result, "tool", None),
            "error": error,
        }
        dashboard_trace = [
            {
                "kind": "patch_execution",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "action": plan.action,
                "status": status,
                "applied": applied,
                "restored": restored,
                "operation_count": report_section["operation_count"],
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
            evidence_manifest_entries=[_manifest_entry(item, status=status) for item in artifacts],
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
                    "effective_status": status,
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
    ) -> CapabilityRollbackResult:
        rollback_artifacts = _tool_artifacts(data)
        if rollback_artifacts:
            result.artifacts.extend(rollback_artifacts)
            result.evidence_manifest_entries.extend(
                _manifest_entry(item, status="ok" if restored else "failed")
                for item in rollback_artifacts
            )
        status = "ok" if restored else _normalized_status(getattr(tool_result, "status", None))
        if status not in {"ok", "unavailable"}:
            status = "failed"
        result.rollback_plan["status"] = "completed" if restored else "failed"
        result.after_snapshot["rollback_output"] = _file_snapshot(data.get("restored_path"))
        result.dashboard_trace.append(
            {
                "kind": "patch_rollback_verification",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "status": status,
                "restored": restored,
                "restored_path": data.get("restored_path"),
                "restored_sha256": data.get("restored_sha256"),
            }
        )
        verification = {
            "status": status,
            "restored": restored,
            "restored_path": data.get("restored_path"),
            "source_sha256": data.get("source_sha256") or result.rollback_plan.get("source_sha256"),
            "restored_sha256": data.get("restored_sha256"),
            "error": getattr(tool_result, "error", None),
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
            details={
                **verification,
                "artifacts": list(data.get("artifacts") or []),
            },
        )

    def _issue_result_identity(self, result: CapabilityExecutionResult) -> None:
        old_identity = result.provenance.get(_RESULT_IDENTITY_KEY) if isinstance(result.provenance, Mapping) else None
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
        supplied = result.provenance.get(_RESULT_IDENTITY_KEY) if isinstance(result.provenance, Mapping) else None
        if not isinstance(supplied, Mapping):
            raise ValueError("patch_executor result identity is missing")
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
            raise ValueError("capability result does not belong to this patch_executor provider")
        if _canonical_json(dict(supplied)) != _canonical_json(expected):
            raise ValueError("patch_executor result identity does not match the result contents")
        if self._issued_result_identities.get(digest) != canonical:
            raise ValueError("patch_executor result identity was not issued by this provider instance")
        plan_digest = str(expected.get("plan_digest") or "")
        if plan_digest not in self._issued_plan_identities:
            raise ValueError("patch_executor result references an unknown plan identity")


class PatchExecutorMockProvider(MockCapabilityProvider):
    def __init__(self) -> None:
        super().__init__("patch_executor")


def _normalize_action(action: str) -> str:
    normalized = str(action or "").strip().lower().replace("-", "_")
    if normalized in {"dry_run", "dryrun"}:
        return "plan"
    return normalized


def _target_path(request: CapabilityRequest) -> Path:
    if not request.target.path:
        raise ValueError("patch_executor requires a file target")
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
    out_root = Path(str((context or {}).get("out_dir") or target_path.parent / ".reverse-analyzer")).resolve()
    artifact_dir = Path(str(params.get("artifact_dir") or out_root / "patch" / session_id)).expanduser().resolve()
    suffix = target_path.suffix
    if action == "rollback":
        default_output = artifact_dir / "rolled_back" / f"{target_path.stem}.restored{suffix}"
    else:
        default_output = artifact_dir / "patched" / f"{target_path.stem}.patched{suffix}"
    out_path = Path(str(params.get("out_path") or default_output)).expanduser().resolve()
    rollback_out_path = Path(
        str(params.get("rollback_out_path") or artifact_dir / "rollback-check" / f"{target_path.stem}.restored{suffix}")
    ).expanduser().resolve()
    params.update(
        {
            "artifact_dir": str(artifact_dir),
            "out_path": str(out_path),
            "rollback_out_path": str(rollback_out_path),
        }
    )
    return params


def _validate_action(plan: CapabilityPlan) -> ToolResult:
    target_path = plan.target.path or ""
    params = plan.parameters
    if plan.action == "rollback":
        rollback = params.get("rollback")
        if rollback is None:
            return _failed_result("binary_patch_rollback", "rollback parameter is required")
        return binary_patch_rollback_plan(
            target_path,
            rollback=rollback,
            out_path=params["out_path"],
            apply=False,
            artifact_dir=params["artifact_dir"],
        )
    patch_plan = params.get("plan")
    if patch_plan is None:
        return _failed_result("validate_patch_plan", "plan parameter is required")
    if plan.action == "apply":
        return binary_patch_apply_plan(
            target_path,
            plan=patch_plan,
            out_path=params["out_path"],
            apply=False,
            artifact_dir=params["artifact_dir"],
            plan_source_path=params.get("plan_source_path"),
        )
    return validate_patch_plan(target_path, plan=patch_plan)


def _execute_action(plan: CapabilityPlan) -> ToolResult:
    target_path = plan.target.path or ""
    params = plan.parameters
    if plan.action == "validate":
        return validate_patch_plan(target_path, plan=params["plan"])
    if plan.action in {"plan", "apply"}:
        return binary_patch_apply_plan(
            target_path,
            plan=params["plan"],
            out_path=params["out_path"],
            apply=plan.action == "apply",
            artifact_dir=params["artifact_dir"],
            plan_source_path=params.get("plan_source_path"),
        )
    if plan.action == "rollback":
        return binary_patch_rollback_plan(
            target_path,
            rollback=params["rollback"],
            out_path=params["out_path"],
            apply=True,
            artifact_dir=params["artifact_dir"],
        )
    return _failed_result("patch_executor", f"unsupported action: {plan.action}")


def _validation_tool_ok(action: str, status: str, data: Mapping[str, Any]) -> bool:
    if action in {"plan", "validate"}:
        return (
            status == "ok"
            and data.get("status") == "ok"
            and data.get("valid") is True
            and data.get("dry_run") is True
            and data.get("artifacts") == []
        )
    return (
        status == "planned"
        and data.get("status") == "planned"
        and data.get("dry_run") is True
        and data.get("artifacts") == []
    )


def _validation_failure_status(validation: CapabilityValidation) -> str:
    if any(str(item.get("status") or "").casefold() == "unavailable" for item in validation.checks):
        return "unavailable"
    return "failed"


def _execution_outcome(
    plan: CapabilityPlan,
    tool_result: ToolResult,
    target_path: Path | None,
) -> tuple[str, bool, bool, dict[str, Any]]:
    data = _result_data(tool_result)
    raw_status = _normalized_status(getattr(tool_result, "status", None))
    verification: dict[str, Any] = {"errors": []}
    if raw_status == "unavailable":
        return "unavailable", False, False, verification
    if raw_status == "failed":
        return "failed", False, False, verification

    errors: list[str] = []
    if plan.action == "plan":
        if (
            raw_status != "planned"
            or data.get("status") != "planned"
            or data.get("dry_run") is not True
            or data.get("artifacts") != []
        ):
            errors.append("plan action must remain a non-materializing dry run")
        if errors:
            verification["errors"] = errors
            return "failed", False, False, verification
        return "planned", False, False, verification
    if plan.action == "validate":
        if (
            raw_status != "ok"
            or data.get("status") != "ok"
            or data.get("valid") is not True
            or data.get("dry_run") is not True
            or data.get("artifacts") != []
        ):
            errors.append("validate action did not return a successful non-materializing verification")
        if errors:
            verification["errors"] = errors
            return "failed", False, False, verification
        return "ok", False, False, verification
    if plan.action == "apply":
        errors, details = _verify_apply_materialization(plan, tool_result, data, target_path)
        verification.update(details)
        verification["errors"] = errors
        return ("ok", True, False, verification) if not errors else ("failed", False, False, verification)
    if plan.action == "rollback":
        expected_output = _resolved_path(plan.parameters.get("out_path"))
        errors, restored_snapshot = _verify_rollback_materialization(
            tool_result,
            data,
            expected_restored_path=expected_output,
            expected_source_sha256=data.get("source_sha256"),
            expected_patched_sha256=plan.precondition_hash,
        )
        verification["errors"] = errors
        verification["restored_snapshot"] = restored_snapshot
        return ("ok", False, True, verification) if not errors else ("failed", False, False, verification)
    verification["errors"] = [f"unsupported patch_executor action: {plan.action}"]
    return "failed", False, False, verification


def _verify_apply_materialization(
    plan: CapabilityPlan,
    tool_result: ToolResult,
    data: Mapping[str, Any],
    target_path: Path | None,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    details: dict[str, Any] = {}
    expected_output = _resolved_path(plan.parameters.get("out_path"))
    actual_output = _resolved_path(data.get("patched_path"))
    rollback_path = _resolved_path(data.get("rollback_path"))
    expected_manifest = _resolved_path(Path(str(plan.parameters.get("artifact_dir"))) / "patch_manifest.json")
    expected_rollback = _resolved_path(Path(str(plan.parameters.get("artifact_dir"))) / "rollback.json")

    if (
        _normalized_status(getattr(tool_result, "status", None)) != "ok"
        or data.get("status") != "ok"
        or data.get("dry_run") is not False
    ):
        errors.append("apply action did not materialize a patch")
    if expected_output is None or actual_output is None or not _same_path(expected_output, actual_output):
        errors.append("patch engine output path does not match the planned output path")
    target_snapshot = _file_snapshot(target_path)
    output_snapshot = _file_snapshot(actual_output)
    if not _hashes_equal(target_snapshot.get("sha256"), plan.precondition_hash):
        errors.append("source target changed while applying the patch")
    if not output_snapshot.get("exists") or not _hashes_equal(output_snapshot.get("sha256"), data.get("patched_sha256")):
        errors.append("patched output hash does not match the materialized file")
    if not _hashes_equal(data.get("source_sha256"), plan.precondition_hash):
        errors.append("patch engine source hash does not match the planned target")
    if rollback_path is None or expected_rollback is None or not _same_path(rollback_path, expected_rollback):
        errors.append("rollback manifest path does not match the planned artifact path")

    artifact_paths = _artifact_path_set(data)
    for label, required_path in (
        ("patched output", expected_output),
        ("patch manifest", expected_manifest),
        ("rollback manifest", expected_rollback),
    ):
        if required_path is None or _path_key(required_path) not in artifact_paths:
            errors.append(f"{label} is missing from patch engine artifacts")

    patch_manifest = _read_json_mapping(expected_manifest)
    rollback_manifest = _read_json_mapping(expected_rollback)
    if patch_manifest is None:
        errors.append("patch manifest is missing or invalid JSON")
    else:
        if not _hashes_equal(patch_manifest.get("source_sha256"), plan.precondition_hash):
            errors.append("patch manifest source hash is inconsistent")
        if not _hashes_equal(patch_manifest.get("patched_sha256"), data.get("patched_sha256")):
            errors.append("patch manifest output hash is inconsistent")
        if actual_output is None or not _same_path(_resolved_path(patch_manifest.get("patched_path")), actual_output):
            errors.append("patch manifest output path is inconsistent")
    if rollback_manifest is None:
        errors.append("rollback manifest is missing or invalid JSON")
    else:
        if not _hashes_equal(rollback_manifest.get("source_sha256"), plan.precondition_hash):
            errors.append("rollback manifest source hash is inconsistent")
        if not _hashes_equal(rollback_manifest.get("patched_sha256"), data.get("patched_sha256")):
            errors.append("rollback manifest patched hash is inconsistent")
        if not isinstance(rollback_manifest.get("operations"), list):
            errors.append("rollback manifest operations are missing")
    details["rollback_manifest_snapshot"] = _file_snapshot(expected_rollback)
    return _dedupe(errors), details


def _verify_rollback_inputs(
    patched_path: Path | None,
    rollback_manifest: Path | None,
    restored_path: Path | None,
    rollback_plan: Mapping[str, Any],
) -> str | None:
    if patched_path is None or rollback_manifest is None or restored_path is None:
        return "rollback metadata is incomplete"
    patched_snapshot = _file_snapshot(patched_path)
    manifest_snapshot = _file_snapshot(rollback_manifest)
    if not _hashes_equal(patched_snapshot.get("sha256"), rollback_plan.get("patched_sha256")):
        return "patched copy changed after execution; refusing rollback"
    if not _hashes_equal(manifest_snapshot.get("sha256"), rollback_plan.get("rollback_manifest_sha256")):
        return "rollback manifest changed after execution; refusing rollback"
    if restored_path.exists() or _paths_collide(restored_path, patched_path) or _paths_collide(restored_path, rollback_manifest):
        return "rollback output path must be a new path distinct from rollback inputs"
    return None


def _verify_rollback_materialization(
    tool_result: ToolResult,
    data: Mapping[str, Any],
    *,
    expected_restored_path: Path | None,
    expected_source_sha256: Any,
    expected_patched_sha256: Any,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    actual_path = _resolved_path(data.get("restored_path"))
    snapshot = _file_snapshot(actual_path)
    if (
        _normalized_status(getattr(tool_result, "status", None)) != "ok"
        or data.get("status") != "ok"
        or data.get("dry_run") is not False
    ):
        errors.append("rollback did not materialize a restored copy")
    if expected_restored_path is None or actual_path is None or not _same_path(expected_restored_path, actual_path):
        errors.append("restored output path does not match the planned rollback output")
    if not snapshot.get("exists") or not _hashes_equal(snapshot.get("sha256"), data.get("restored_sha256")):
        errors.append("restored output hash does not match the materialized file")
    if not _hashes_equal(data.get("restored_sha256"), expected_source_sha256):
        errors.append("restored output hash does not match the original source hash")
    if not _hashes_equal(data.get("source_sha256"), expected_source_sha256):
        errors.append("rollback engine source hash is inconsistent")
    if not _hashes_equal(data.get("patched_sha256"), expected_patched_sha256):
        errors.append("rollback engine patched hash is inconsistent")
    artifact_paths = _artifact_path_set(data)
    if expected_restored_path is None or _path_key(expected_restored_path) not in artifact_paths:
        errors.append("restored output is missing from rollback artifacts")
    manifest_items = [
        item
        for item in data.get("artifacts") or []
        if isinstance(item, Mapping) and item.get("kind") == "patch-rollback-manifest"
    ]
    if len(manifest_items) != 1:
        errors.append("rollback verification manifest is missing from rollback artifacts")
    else:
        manifest = _read_json_mapping(_resolved_path(manifest_items[0].get("path")))
        if manifest is None:
            errors.append("rollback verification manifest is missing or invalid JSON")
        elif not _hashes_equal(manifest.get("restored_sha256"), expected_source_sha256):
            errors.append("rollback verification manifest restored hash is inconsistent")
    return _dedupe(errors), snapshot


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
    before = payload.get("before_snapshot") if isinstance(payload.get("before_snapshot"), Mapping) else {}
    return {
        "schema_version": _IDENTITY_SCHEMA_VERSION,
        "capability": payload.get("capability"),
        "provider": payload.get("provider"),
        "session_id": payload.get("session_id"),
        "action": payload.get("action"),
        "target_path": target.get("path") or before.get("path"),
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
    return str(identity.get("digest")) if isinstance(identity, Mapping) and identity.get("digest") else None


def _parameter_input_snapshots(parameters: Mapping[str, Any]) -> dict[str, Any]:
    snapshots: dict[str, Any] = {}
    for key in ("plan", "rollback", "plan_source_path"):
        value = parameters.get(key)
        if value is None:
            continue
        if isinstance(value, (str, Path)):
            path = _resolved_path(value)
            snapshots[key] = {"kind": "file", **_file_snapshot(path)}
        else:
            snapshots[key] = {"kind": "inline", "sha256": _canonical_digest(value)}

    plan_value = parameters.get("plan")
    plan_payload: Mapping[str, Any] | None = plan_value if isinstance(plan_value, Mapping) else None
    plan_dir: Path | None = None
    if isinstance(plan_value, (str, Path)):
        plan_path = _resolved_path(plan_value)
        plan_dir = plan_path.parent if plan_path is not None else None
        plan_payload = _read_json_mapping(plan_path)
    if isinstance(plan_payload, Mapping):
        dependencies = _find_plan_file_dependencies(plan_payload, base_dir=plan_dir)
        if dependencies:
            snapshots["plan_dependencies"] = dependencies
    return snapshots


def _find_plan_file_dependencies(value: Any, *, base_dir: Path | None, prefix: str = "$") -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    if isinstance(value, Mapping):
        for key in sorted(value, key=lambda item: str(item)):
            item = value[key]
            pointer = f"{prefix}.{key}"
            if str(key) in {"payload_file", "payload_path"} and isinstance(item, (str, Path)):
                candidate = Path(str(item)).expanduser()
                if not candidate.is_absolute() and base_dir is not None:
                    candidate = base_dir / candidate
                path = _resolved_path(candidate)
                dependencies.append({"field": pointer, **_file_snapshot(path)})
            else:
                dependencies.extend(_find_plan_file_dependencies(item, base_dir=base_dir, prefix=pointer))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            dependencies.extend(_find_plan_file_dependencies(item, base_dir=base_dir, prefix=f"{prefix}[{index}]"))
    return dependencies


def _tool_artifacts(data: Mapping[str, Any]) -> list[CapabilityArtifact]:
    artifacts: list[CapabilityArtifact] = []
    for item in data.get("artifacts") or []:
        if not isinstance(item, Mapping) or not item.get("path"):
            continue
        snapshot = _file_snapshot(item["path"])
        artifacts.append(
            CapabilityArtifact(
                path=str(item["path"]),
                kind=str(item.get("kind") or "patch-artifact"),
                description=str(item.get("name") or Path(str(item["path"])).name),
                metadata={"materialized": bool(snapshot.get("exists")), "snapshot": snapshot},
            )
        )
    return artifacts


def _require_artifact_integrity(artifacts: list[CapabilityArtifact]) -> None:
    for artifact in artifacts or []:
        metadata = artifact.metadata if isinstance(artifact.metadata, Mapping) else {}
        if not metadata.get("materialized"):
            continue
        expected = metadata.get("snapshot") if isinstance(metadata.get("snapshot"), Mapping) else {}
        current = _file_snapshot(artifact.path)
        if not current.get("exists") or not _hashes_equal(current.get("sha256"), expected.get("sha256")):
            raise ValueError(f"patch artifact changed after execution: {artifact.path}")


def _manifest_entry(artifact: CapabilityArtifact, *, status: str) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "tool": "patch_executor",
        "status": status,
        "role": "patch-evidence",
    }


def _artifact_path_set(data: Mapping[str, Any]) -> set[str]:
    paths: set[str] = set()
    for item in data.get("artifacts") or []:
        if isinstance(item, Mapping) and item.get("path"):
            path = _resolved_path(item.get("path"))
            if path is not None:
                paths.add(_path_key(path))
    return paths


def _result_data(result: Any) -> dict[str, Any]:
    return dict(result.data) if isinstance(getattr(result, "data", None), Mapping) else {}


def _failed_result(tool: str, error: str, *, status: str = "failed") -> ToolResult:
    normalized = status if status in {"failed", "unavailable"} else "failed"
    return ToolResult(tool=tool, status=normalized, error=error, data={"status": normalized, "artifacts": []})


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


def _target_format(path: str | Path | None) -> str:
    candidate = _resolved_path(path)
    if candidate is None:
        return "unknown"
    try:
        with candidate.open("rb") as handle:
            magic = handle.read(4)
    except (OSError, ValueError):
        return "unknown"
    if magic.startswith(b"MZ"):
        return "pe"
    if magic == b"\x7fELF":
        return "elf"
    return "binary"


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


def _paths_collide(left: Path, right: Path) -> bool:
    if _same_path(left, right):
        return True
    try:
        return left.exists() and right.exists() and left.samefile(right)
    except OSError:
        return False


def _same_path(left: Path | None, right: Path | None) -> bool:
    return left is not None and right is not None and _path_key(left) == _path_key(right)


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
    return _valid_sha256(left) and _valid_sha256(right) and str(left).casefold() == str(right).casefold()


def _normalized_status(value: Any) -> str:
    status = str(value or "failed").strip().casefold()
    return status if status in {"ok", "planned", "failed", "unavailable"} else "failed"


def _canonical_digest(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def _canonical_json(value: Any) -> str:
    return json.dumps(_identity_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


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


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
