"""Capability provider for deterministic, read-only hook target resolution."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from reverse_analyzer.core.capabilities.models import (
    CapabilityArtifact,
    CapabilityArtifactBundle,
    CapabilityExecutionResult,
    CapabilityPlan,
    CapabilityRequest,
    CapabilityRollbackResult,
    CapabilityValidation,
)
from reverse_analyzer.providers.hook_targets import (
    HookTargetResolution,
    common_hook_targets,
    live_hook_target_capability,
    plan_live_common_hook_target,
    resolve_common_hook_target,
    resolve_live_common_hook_target,
)


_ACTION_ALIASES = {
    "resolve": "resolve_offline",
    "resolve_offline": "resolve_offline",
    "offline": "resolve_offline",
    "resolve_live": "resolve_live",
    "live": "resolve_live",
    "plan_live": "plan_live",
    "plan_live_target": "plan_live",
}
_SAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, default=str).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _target_payload(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict"):
        payload = value.to_dict()
        return dict(payload) if isinstance(payload, Mapping) else {}
    return _mapping(value)


def _normalize_action(value: Any) -> str:
    return _ACTION_ALIASES.get(
        str(value or "").strip().lower().replace("-", "_"), ""
    )


def _safe_session_id(value: Any) -> str:
    text = _SAFE_SEGMENT_RE.sub("-", str(value or "session")).strip(".-")
    return text[:96] or "session"


def _artifact_specs(session_id: str) -> list[dict[str, str]]:
    root = f"hook-targets/{_safe_session_id(session_id)}"
    return [
        {
            "path": f"{root}/resolution.json",
            "kind": "hook-target-resolution",
            "description": "Resolved hook target and executable-range evidence.",
        },
        {
            "path": f"{root}/audit.json",
            "kind": "hook-target-audit",
            "description": "Read-only capability lifecycle audit record.",
        },
        {
            "path": f"{root}/manifest.json",
            "kind": "hook-target-manifest",
            "description": "Materialized hook target artifact manifest.",
        },
    ]


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode(
        "utf-8"
    )
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "size": len(encoded)}


class HookTargetResolverProvider:
    """Expose the existing hook resolver through the capability lifecycle."""

    capability_name = "hook_target_resolver"
    provider_name = "deterministic_hook_target_resolver"
    priority = 10

    def __init__(self) -> None:
        self._instance_id = uuid.uuid4().hex

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        return (
            request.capability == self.capability_name
            and _normalize_action(request.action) in set(_ACTION_ALIASES.values())
        )

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        del context
        action = _normalize_action(request.action)
        params = _mapping(request.params)
        raw_specification = params.get("specification", params.get("target_specification"))
        if raw_specification is None:
            raw_specification = {
                key: value
                for key, value in params.items()
                if key not in {"modules", "load_if_missing"}
            }
        if isinstance(raw_specification, str):
            specification: Any = {"target": raw_specification}
        elif isinstance(raw_specification, Mapping):
            specification = dict(raw_specification)
        else:
            specification = raw_specification
        modules = params.get("modules", [])
        normalized_modules = (
            [dict(item) for item in modules if isinstance(item, Mapping)]
            if isinstance(modules, Sequence)
            and not isinstance(modules, (str, bytes, bytearray))
            else []
        )
        session_id = str(request.session_id or uuid.uuid4().hex)
        target = _target_payload(request.target)
        precondition_hash = _canonical_hash(
            {
                "capability": self.capability_name,
                "action": action,
                "target": target,
                "specification": specification,
                "modules": normalized_modules,
            }
        )
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=action or str(request.action),
            parameters={
                "specification": specification,
                "modules": normalized_modules,
                "load_if_missing": params.get("load_if_missing") is True,
                "read_only": True,
            },
            steps=[
                {"name": "validate_specification", "mutates_target": False},
                {"name": action or "unsupported_action", "mutates_target": False},
                {"name": "persist_resolution_evidence", "mutates_target": False},
            ],
            precondition_hash=precondition_hash,
            before_snapshot={
                "captured_at": _utc_now(),
                "target_identity": target,
                "catalogue_target_count": len(common_hook_targets()),
                "live_capability": live_hook_target_capability(),
                "target_mutation": False,
            },
            rollback_plan={
                "supported": True,
                "required": False,
                "active": False,
                "strategy": "read_only_noop",
                "precondition_hash": precondition_hash,
            },
            provenance={
                **_mapping(request.provenance),
                "provider_instance": self._instance_id,
                "resolver": "reverse_analyzer.providers.hook_targets",
                "read_only": True,
            },
        )

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        del context
        checks: list[dict[str, Any]] = []
        errors: list[str] = []

        def check(name: str, ok: bool, message: str) -> None:
            checks.append({"name": name, "status": "ok" if ok else "failed", "message": message})
            if not ok:
                errors.append(message)

        action = _normalize_action(plan.action)
        specification = plan.parameters.get("specification")
        modules = plan.parameters.get("modules")
        check(
            "capability_identity",
            plan.capability == self.capability_name and plan.provider == self.provider_name,
            "plan capability/provider identity must match hook target resolver",
        )
        check(
            "provider_instance",
            plan.provenance.get("provider_instance") == self._instance_id,
            "plan was not issued by this provider instance",
        )
        check("action", bool(action), "unsupported hook target resolver action")
        check(
            "specification",
            isinstance(specification, Mapping) and bool(specification),
            "hook target specification must be a non-empty object",
        )
        check(
            "modules",
            isinstance(modules, list) and all(isinstance(item, Mapping) for item in modules),
            "modules must be a list of objects",
        )
        check(
            "precondition_hash",
            isinstance(plan.precondition_hash, str) and len(plan.precondition_hash) == 64,
            "precondition hash must be a SHA-256 digest",
        )
        return CapabilityValidation(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=plan.session_id,
            ok=not errors,
            checks=checks,
            errors=errors,
        )

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        del context
        validation = self.validate(plan)
        if validation.ok:
            resolution = self._resolve(plan)
            status = resolution.status
        else:
            resolution = HookTargetResolution(
                status="failed",
                method="validation",
                errors=list(validation.errors),
                provenance={"read_only": True},
            )
            status = "failed"
        completed_at = _utc_now()
        resolution_payload = resolution.to_dict()
        specs = _artifact_specs(plan.session_id)
        artifacts = [
            CapabilityArtifact(
                path=item["path"],
                kind=item["kind"],
                description=item["description"],
                metadata={"materialized": False, "session_id": plan.session_id},
            )
            for item in specs
        ]
        manifest_entries = [
            {
                "path": item.path,
                "kind": item.kind,
                "description": item.description,
                "status": status,
                "session_id": plan.session_id,
            }
            for item in artifacts
        ]
        report_section = {
            "capability": self.capability_name,
            "provider": self.provider_name,
            "action": plan.action,
            "status": status,
            "session_id": plan.session_id,
            "target_identity": _target_payload(plan.target),
            "method": resolution.method,
            "resolved_target": resolution.target,
            "address": resolution.address,
            "rva": resolution.rva,
            "confidence": resolution.confidence,
            "production_ready": resolution.production_ready,
            "evidence_tier": resolution.evidence_tier,
            "read_only": True,
            "errors": list(resolution.errors),
            "warnings": list(resolution.warnings),
        }
        lifecycle = [
            {"kind": "plan", "ts": completed_at, "message": "hook target resolution planned"},
            {"kind": "validate", "ts": completed_at, "message": "hook target plan validated", "ok": validation.ok},
            {"kind": "execute", "ts": completed_at, "message": "hook target resolution completed", "status": status},
        ]
        return CapabilityExecutionResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=dict(plan.before_snapshot),
            after_snapshot={
                "captured_at": completed_at,
                "status": status,
                "resolution": resolution_payload,
                "target_mutated": False,
            },
            rollback_plan={**dict(plan.rollback_plan), "status": "not_required"},
            artifacts=artifacts,
            evidence_manifest_entries=manifest_entries,
            report_section=report_section,
            dashboard_trace=[
                {
                    "kind": "hook_target_resolution",
                    "capability": self.capability_name,
                    "provider": self.provider_name,
                    "action": plan.action,
                    "status": status,
                    "session_id": plan.session_id,
                    "target": resolution.target,
                    "method": resolution.method,
                    "production_ready": resolution.production_ready,
                }
            ],
            provenance={
                **dict(plan.provenance),
                "precondition_hash": plan.precondition_hash,
                "plan": plan.to_dict(),
                "validation": validation.to_dict(),
                "lifecycle_events": lifecycle,
                "target_mutation": False,
            },
        )

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        result.rollback_plan.update(
            {"status": "completed", "active": False, "restored": True}
        )
        result.dashboard_trace.append(
            {
                "kind": "hook_target_rollback",
                "status": "completed",
                "restored": True,
                "session_id": result.session_id,
            }
        )
        return CapabilityRollbackResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            ok=True,
            restored=True,
            details={"status": "not_required", "reason": "resolver is read-only"},
        )

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        del context
        root = Path(out_dir).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        specs = _artifact_specs(result.session_id)
        paths = {item["kind"]: (root / item["path"]).resolve() for item in specs}
        if any(root != path and root not in path.parents for path in paths.values()):
            raise ValueError("hook target artifact path escapes output directory")

        resolution_meta = _atomic_write_json(
            paths["hook-target-resolution"],
            _mapping(result.after_snapshot.get("resolution")),
        )
        audit_payload = {
            "schema_version": 1,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "action": result.action,
            "status": result.status,
            "target_identity": _target_payload(result.target),
            "precondition_hash": result.provenance.get("precondition_hash"),
            "before_snapshot": dict(result.before_snapshot),
            "after_snapshot": dict(result.after_snapshot),
            "rollback_plan": dict(result.rollback_plan),
            "provenance": dict(result.provenance),
            "evidence_manifest_entries": list(result.evidence_manifest_entries),
            "report_section": dict(result.report_section),
            "dashboard_trace": list(result.dashboard_trace),
            "events": list(result.provenance.get("lifecycle_events") or []),
        }
        audit_meta = _atomic_write_json(paths["hook-target-audit"], audit_payload)
        manifest_payload = {
            "schema_version": 1,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "status": result.status,
            "generated_at": _utc_now(),
            "artifacts": [
                {**specs[0], **resolution_meta},
                {**specs[1], **audit_meta},
            ],
        }
        manifest_meta = _atomic_write_json(
            paths["hook-target-manifest"], manifest_payload
        )
        metadata = {
            "hook-target-resolution": resolution_meta,
            "hook-target-audit": audit_meta,
            "hook-target-manifest": manifest_meta,
        }
        result.artifacts = [
            CapabilityArtifact(
                path=item["path"],
                kind=item["kind"],
                description=item["description"],
                metadata={"materialized": True, **metadata[item["kind"]]},
            )
            for item in specs
        ]
        result.evidence_manifest_entries = [
            {
                "path": item.path,
                "kind": item.kind,
                "description": item.description,
                "status": result.status,
                **metadata[item.kind],
            }
            for item in result.artifacts
        ]
        result.report_section.update(
            {"artifact_count": len(result.artifacts), "artifacts_materialized": True}
        )
        return CapabilityArtifactBundle(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            artifacts=list(result.artifacts),
            manifest_entries=list(result.evidence_manifest_entries),
        )

    @staticmethod
    def _resolve(plan: CapabilityPlan) -> HookTargetResolution:
        specification = _mapping(plan.parameters.get("specification"))
        if plan.action == "resolve_live":
            return resolve_live_common_hook_target(
                specification,
                load_if_missing=plan.parameters.get("load_if_missing") is True,
            )
        if plan.action == "plan_live":
            return plan_live_common_hook_target(specification)
        return resolve_common_hook_target(
            specification,
            modules=list(plan.parameters.get("modules") or []),
        )


__all__ = ["HookTargetResolverProvider"]
