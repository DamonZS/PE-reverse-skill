from __future__ import annotations

from reverse_analyzer.core.capabilities.models import (
    CapabilityArtifact,
    CapabilityArtifactBundle,
    CapabilityExecutionResult,
    CapabilityPlan,
    CapabilityRequest,
    CapabilityRollbackResult,
    CapabilityValidation,
)
from reverse_analyzer.providers.base import CapabilityProvider


class MockCapabilityProvider(CapabilityProvider):
    def __init__(self, capability_name: str, provider_name: str = "mock", priority: int = 100) -> None:
        self.capability_name = capability_name
        self.provider_name = provider_name
        self.priority = priority

    def plan(self, request: CapabilityRequest, context=None) -> CapabilityPlan:
        target = request.target
        before_snapshot = {"action": request.action}
        if getattr(target, "pid", None) is not None:
            before_snapshot["pid"] = target.pid
        if getattr(target, "path", None):
            before_snapshot["path"] = target.path
        return CapabilityPlan(
            capability=request.capability,
            provider=self.provider_name,
            session_id=request.session_id or f"{request.capability}-session",
            target=request.target,
            action=request.action,
            steps=[{"step": "mock_plan", "status": "ok"}],
            precondition_hash=f"mock-{request.capability}-{request.action}",
            before_snapshot=before_snapshot,
            rollback_plan={"supported": True, "mode": "mock"},
            provenance=request.provenance,
        )

    def validate(self, plan: CapabilityPlan, context=None) -> CapabilityValidation:
        return CapabilityValidation(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            ok=True,
            checks=[{"name": "mock_validate", "status": "ok"}],
        )

    def execute(self, plan: CapabilityPlan, context=None) -> CapabilityExecutionResult:
        artifact_path = f"{plan.capability}/{plan.capability}_{plan.action}.json"
        return CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status="mocked",
            action=plan.action,
            target=plan.target,
            before_snapshot=plan.before_snapshot,
            after_snapshot={"mock": True, "action": plan.action},
            rollback_plan=plan.rollback_plan,
            artifacts=[
                CapabilityArtifact(
                    path=artifact_path,
                    kind="capability-audit",
                    description=f"Mock artifact for {plan.capability}:{plan.action}",
                )
            ],
            evidence_manifest_entries=[
                {
                    "path": artifact_path,
                    "kind": "capability-audit",
                    "tool": plan.capability,
                    "status": "ok",
                    "role": "audit-artifact",
                }
            ],
            report_section={
                "status": "mocked",
                "provider": plan.provider,
                "capability": plan.capability,
                "action": plan.action,
            },
            dashboard_trace=[
                {
                    "kind": "capability_execution",
                    "capability": plan.capability,
                    "provider": plan.provider,
                    "action": plan.action,
                    "status": "mocked",
                }
            ],
            provenance={**plan.provenance, "precondition_hash": plan.precondition_hash},
        )

    def rollback(self, result: CapabilityExecutionResult, context=None) -> CapabilityRollbackResult:
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=True,
            restored=True,
            details={"mode": "mock"},
        )

    def collect_artifacts(self, result: CapabilityExecutionResult, out_dir: str, context=None) -> CapabilityArtifactBundle:
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=list(result.artifacts or []),
            manifest_entries=list(result.evidence_manifest_entries or []),
        )
