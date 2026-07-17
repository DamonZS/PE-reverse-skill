"""Capability provider for executing LLM jailbreak campaigns."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, is_dataclass
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

from reverse_analyzer.core.capabilities.models import (
    CapabilityArtifact,
    CapabilityArtifactBundle,
    CapabilityExecutionResult,
    CapabilityPlan,
    CapabilityRequest,
    CapabilityRollbackResult,
    CapabilityValidation,
    TargetIdentity,
)


_SCHEMA_VERSION = 1
_SUPPORTED_ACTIONS = {"run", "resume"}
_ACTION_ALIASES = {
    "campaign": "run",
    "execute": "run",
    "start": "run",
    "continue": "resume",
}
_DEFAULT_BASE_URL = "https://api.openai.com/v1"
_DEFAULT_MODEL = "gpt-4.1-mini"
_DEFAULT_API_KEY_ENV = "OPENAI_API_KEY"
_DEFAULT_TIMEOUT = 60.0
_DEFAULT_MAX_ATTEMPTS = 20
_DEFAULT_MAX_ROUNDS = 5
_DEFAULT_ATTACK_MODES = ("builtin",)
_DEFAULT_SEMANTIC_JUDGE = "disabled"
_SUPPORTED_ATTACK_MODES = ("builtin", "pair", "tap", "crescendo", "evolution")
_SUPPORTED_SEMANTIC_JUDGES = ("disabled", "heuristic", "model")
_MAX_CAMPAIGN_BYTES = 8 * 1024 * 1024
_MAX_TIMEOUT = 3600.0
_MAX_ATTEMPTS = 100_000
_MAX_ROUNDS = 10_000
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SESSION_RE = re.compile(r"^[A-Za-z0-9_.-]{1,256}$")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{4,}")
_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_INLINE_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|authorization)\s*([:=])\s*([^\s,;\"']+)"
)
_SECRET_KEYS = {
    "apikey",
    "authorization",
    "proxyauthorization",
    "openaiapikey",
    "anthropicapikey",
    "accesstoken",
    "refreshtoken",
    "bearertoken",
}
_CORE_MODULES = (
    "reverse_analyzer.llm_jailbreak",
    "reverse_analyzer.llm_jailbreak.campaign",
)
_CORE_FUNCTIONS = ("execute_campaign", "run_campaign")
_CORE_RUNNER_CLASSES = ("JailbreakCampaignRunner", "CampaignRunner")
_ARTIFACT_SPECS = (
    ("campaign.json", "llm-jailbreak-campaign", "Jailbreak campaign definition and execution settings"),
    ("result.json", "llm-jailbreak-result", "Normalized jailbreak campaign result"),
    ("attempts.json", "llm-jailbreak-attempts", "Individual jailbreak attempts"),
    ("rollback.json", "llm-jailbreak-rollback", "Local campaign rollback record"),
)
_ENGINE_ARTIFACT_KINDS = {
    "campaign.json": "llm-jailbreak-engine-campaign",
    "attempts.json": "llm-jailbreak-engine-attempts",
    "attempts.jsonl": "llm-jailbreak-engine-attempt-log",
    "transcript.json": "llm-jailbreak-engine-transcript",
    "result.json": "llm-jailbreak-engine-result",
    "manifest.json": "llm-jailbreak-engine-manifest",
    "checkpoint.json": "llm-jailbreak-engine-checkpoint",
    "instruction-assets.json": "llm-jailbreak-instruction-assets",
}


class CoreJailbreakUnavailable(RuntimeError):
    """Raised when the jailbreak core package has no executable entrypoint."""


class LLMJailbreakProvider:
    """Run the real jailbreak campaign engine through the capability lifecycle."""

    capability_name = "llm_jailbreak"
    provider_name = "openai_compatible_jailbreak"
    priority = 10
    supported_actions = tuple(sorted(_SUPPORTED_ACTIONS))

    def __init__(
        self,
        *,
        runner: Optional[Any] = None,
        transport: Optional[Any] = None,
        transport_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        # These are public injection points so tests and local adapters never need
        # to monkeypatch network libraries.
        self.runner = runner
        self.transport = transport
        self.transport_factory = transport_factory
        self._payloads: dict[tuple[str, str], dict[str, Any]] = {}
        self._payload_lock = threading.RLock()

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        return (
            request.capability == self.capability_name
            and _normalize_action(request.action) in _SUPPORTED_ACTIONS
        )

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        del context
        if request.capability != self.capability_name:
            raise ValueError(f"request capability must be {self.capability_name}")
        action = _normalize_action(request.action)
        if action not in _SUPPORTED_ACTIONS:
            raise ValueError(f"unsupported llm_jailbreak action: {request.action!r}")

        session_id = _normalize_session_id(request.session_id)
        parameters = _normalize_request_parameters(request.params, action=action)
        target = _safe_target(request.target, parameters)
        precondition_payload = _precondition_payload(target, parameters, action)
        precondition_hash = _sha256_json(precondition_payload)
        before_snapshot = _before_snapshot(target, parameters, precondition_hash)
        rollback_plan = _planned_rollback(parameters)

        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=target,
            action=action,
            parameters=parameters,
            steps=[
                {"order": 1, "step": "validate_campaign_and_target", "status": "planned"},
                {"order": 2, "step": "build_openai_compatible_transport", "status": "planned"},
                {"order": 3, "step": "execute_adaptive_jailbreak_campaign", "status": "planned"},
                {"order": 4, "step": "score_and_persist_attempts", "status": "planned"},
            ],
            precondition_hash=precondition_hash,
            before_snapshot=before_snapshot,
            rollback_plan=rollback_plan,
            provenance={
                **_redact_secrets(dict(request.provenance or {})),
                "schema_version": _SCHEMA_VERSION,
                "provider": self.provider_name,
                "target_identity": _target_payload(target),
                "checkpoint": _checkpoint_metadata(parameters),
                "api_key_source": {
                    "mode": "environment_variable",
                    "name": parameters["api_key_env"],
                    "value_persisted": False,
                },
            },
        )

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        checks: list[dict[str, Any]] = []
        errors: list[str] = []
        warnings: list[str] = []

        def check(name: str, ok: bool, error: str, **details: Any) -> None:
            checks.append({"name": name, "status": "ok" if ok else "failed", **details})
            if not ok:
                errors.append(error)

        check(
            "capability",
            plan.capability == self.capability_name,
            f"plan capability must be {self.capability_name}",
            actual=plan.capability,
        )
        check(
            "provider",
            plan.provider == self.provider_name,
            f"plan provider must be {self.provider_name}",
            actual=plan.provider,
        )
        check(
            "action",
            plan.action in _SUPPORTED_ACTIONS,
            f"unsupported llm_jailbreak action: {plan.action!r}",
            actual=plan.action,
        )
        check(
            "session_id",
            bool(_SESSION_RE.fullmatch(str(plan.session_id or ""))),
            "session_id must contain only letters, numbers, '.', '_' or '-' and be at most 256 characters",
            actual=plan.session_id,
        )

        try:
            normalized = _normalize_planned_parameters(plan.parameters, action=plan.action)
            parameters_ok = normalized == plan.parameters
            parameters_error = "" if parameters_ok else "plan parameters are not canonical"
        except (OSError, TypeError, ValueError) as exc:
            normalized = {}
            parameters_ok = False
            parameters_error = str(exc)
        check(
            "parameters",
            parameters_ok,
            parameters_error or "invalid llm_jailbreak parameters",
        )

        target_payload = _target_payload(plan.target)
        target_ok = bool(target_payload.get("display_name") or target_payload.get("path") or target_payload.get("metadata"))
        check("target_identity", target_ok, "target identity must identify the model endpoint")

        if parameters_ok:
            expected_hash = _sha256_json(_precondition_payload(plan.target, normalized, plan.action))
            expected_before = _before_snapshot(plan.target, normalized, expected_hash)
        else:
            expected_hash = ""
            expected_before = {}
        check(
            "precondition_hash",
            bool(expected_hash) and plan.precondition_hash == expected_hash,
            "campaign or target identity changed after planning",
            expected=expected_hash,
            actual=plan.precondition_hash,
        )
        check(
            "before_snapshot",
            bool(expected_before) and plan.before_snapshot == expected_before,
            "before snapshot does not match the planned campaign",
        )

        serialized_plan = _json_value(plan.to_dict())
        secret_key_paths = _secret_key_paths(serialized_plan)
        check(
            "no_inline_api_key",
            not secret_key_paths,
            "plan contains inline API credentials",
            paths=secret_key_paths,
        )

        runner_available, runner_name, runner_error = self._runner_probe(context)
        check(
            "core_runner",
            runner_available,
            runner_error or "reverse_analyzer.llm_jailbreak core runner is unavailable",
            entrypoint=runner_name,
        )
        if not parameters_ok:
            warnings.append("campaign execution is disabled until the plan is regenerated")

        return CapabilityValidation(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=str(plan.session_id or ""),
            ok=not errors,
            checks=checks,
            warnings=_dedupe(warnings),
            errors=_dedupe(errors),
        )

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        validation = self.validate(plan, context=context)
        secret_values = _api_key_values(plan.parameters)
        core_result: dict[str, Any]
        runner_name: Optional[str] = None
        error: Optional[str] = None

        if not validation.ok:
            status = (
                "unavailable"
                if any("core runner" in item.casefold() for item in validation.errors)
                else "failed"
            )
            core_result = {"status": status, "errors": list(validation.errors), "attempts": []}
        else:
            try:
                runner = self._select_runner(context)
                runner_name = _callable_name(runner)
                transport = self._select_transport(plan, context)
                invocation = _runner_invocation(plan, transport=transport, context=context)
                raw_result = _invoke_entrypoint(runner, invocation)
                core_result = _result_mapping(raw_result)
                status = _execution_status(core_result)
            except CoreJailbreakUnavailable as exc:
                status = "unavailable"
                error = _redact_string(str(exc), secret_values)
                core_result = {"status": status, "error": error, "attempts": []}
            except Exception as exc:  # noqa: BLE001 - capability failures become audit evidence
                status = "failed"
                error = _redact_string(f"{type(exc).__name__}: {exc}", secret_values)
                core_result = {"status": status, "error": error, "attempts": []}

        safe_result = _redact_secrets(core_result, secret_values=secret_values)
        attempts = _normalized_attempts(safe_result)
        summary = _execution_summary(plan, safe_result, attempts, status)
        rollback_plan = {
            **_json_value(plan.rollback_plan),
            "status": "ready" if status in {"ok", "failed"} else "not_required",
            "campaign_executed": status in {"ok", "failed"},
        }
        artifacts = _result_artifacts(plan.session_id)
        manifest_entries = [
            _manifest_entry(artifact, plan, status=status, materialized=False)
            for artifact in artifacts
        ]
        campaign_payload = {
            "schema_version": _SCHEMA_VERSION,
            "session_id": plan.session_id,
            "target_identity": _target_payload(plan.target),
            "campaign_id": plan.parameters["campaign_metadata"]["campaign_id"],
            "metadata": plan.parameters["campaign_metadata"],
            "campaign": _audit_campaign_payload(
                plan.parameters["campaign"],
                plan.parameters.get("instruction_source_refs") or [],
            ),
            "execution": _execution_settings(plan.parameters),
        }
        result_payload = {
            "schema_version": _SCHEMA_VERSION,
            "session_id": plan.session_id,
            "summary": summary,
            "result": safe_result,
        }
        attempts_payload = {
            "schema_version": _SCHEMA_VERSION,
            "session_id": plan.session_id,
            "campaign_id": summary["campaign_id"],
            "attempt_count": len(attempts),
            "attempts": attempts,
        }
        rollback_payload = {
            "schema_version": _SCHEMA_VERSION,
            "session_id": plan.session_id,
            **rollback_plan,
        }
        payloads = _redact_secrets(
            {
                "llm-jailbreak-campaign": campaign_payload,
                "llm-jailbreak-result": result_payload,
                "llm-jailbreak-attempts": attempts_payload,
                "llm-jailbreak-rollback": rollback_payload,
            },
            secret_values=secret_values,
        )
        with self._payload_lock:
            self._payloads[(plan.session_id, str(plan.precondition_hash or ""))] = payloads

        report_section = {
            "status": status,
            "strategy": summary["strategy"],
            "attack_modes": summary["attack_modes"],
            "semantic_judge": summary["semantic_judge"],
            "judge_model": summary["judge_model"],
            "instruction_profile": summary.get("instruction_profile"),
            "instruction_files": summary.get("instruction_files"),
            "instruction_bundle_digest": summary.get("instruction_bundle_digest"),
            "instruction_asset_count": summary.get("instruction_asset_count"),
            "instruction_bundle_provenance": summary.get(
                "instruction_bundle_provenance"
            ),
            "success": summary["success"],
            "score": summary["score"],
            "attempt_count": summary["attempt_count"],
            "latency_ms": summary["latency_ms"],
            "model": summary["model"],
            "base_url": summary["base_url"],
            "campaign_id": summary["campaign_id"],
            "capability": self.capability_name,
            "provider": self.provider_name,
            "session_id": plan.session_id,
            "action": plan.action,
            "checkpoint": _checkpoint_metadata(plan.parameters),
            "error": error or safe_result.get("error"),
            "validation": validation.to_dict(),
            "artifact_count": len(artifacts),
        }
        dashboard_trace = [
            {
                "kind": "llm_jailbreak_campaign",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "session_id": plan.session_id,
                **summary,
                "status": status,
            }
        ]
        return CapabilityExecutionResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=plan.before_snapshot,
            after_snapshot={
                "campaign_state": "completed" if status == "ok" else status,
                **summary,
            },
            rollback_plan=rollback_plan,
            artifacts=artifacts,
            evidence_manifest_entries=manifest_entries,
            report_section=_prune(report_section),
            dashboard_trace=dashboard_trace,
            provenance={
                **_redact_secrets(dict(plan.provenance or {}), secret_values=secret_values),
                "precondition_hash": plan.precondition_hash,
                "core_runner": runner_name,
                "checkpoint": _checkpoint_metadata(plan.parameters),
                "api_key_value_persisted": False,
            },
        )

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        self._require_result(result)
        if result.rollback_plan.get("status") == "completed":
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=result.session_id,
                ok=True,
                restored=True,
                details={
                    "status": "already_completed",
                    "mode": "local_campaign_state_cleanup",
                    "remote_requests_reversible": False,
                },
            )

        executed = bool(result.rollback_plan.get("campaign_executed"))
        result.rollback_plan.update(
            {
                "status": "completed" if executed else "not_required",
                "local_state_restored": executed,
                "remote_requests_reversible": False,
            }
        )
        result.after_snapshot["rollback"] = _json_value(result.rollback_plan)
        result.report_section["rollback"] = _json_value(result.rollback_plan)
        result.dashboard_trace.append(
            {
                "kind": "llm_jailbreak_rollback",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "session_id": result.session_id,
                "status": result.rollback_plan["status"],
                "remote_requests_reversible": False,
            }
        )
        key = (result.session_id, str(result.provenance.get("precondition_hash") or ""))
        with self._payload_lock:
            payloads = self._payloads.get(key)
            if payloads is not None:
                payloads["llm-jailbreak-rollback"] = {
                    "schema_version": _SCHEMA_VERSION,
                    "session_id": result.session_id,
                    **_json_value(result.rollback_plan),
                }
        return CapabilityRollbackResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            ok=True,
            restored=executed,
            details={
                "status": result.rollback_plan["status"],
                "mode": "local_campaign_state_cleanup",
                "local_state_restored": executed,
                "remote_requests_reversible": False,
            },
        )

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        del context
        self._require_result(result)
        root = Path(out_dir).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        key = (result.session_id, str(result.provenance.get("precondition_hash") or ""))
        with self._payload_lock:
            payloads = _json_value(self._payloads.get(key) or _fallback_payloads(result))
        payloads["llm-jailbreak-rollback"] = {
            "schema_version": _SCHEMA_VERSION,
            "session_id": result.session_id,
            **_json_value(result.rollback_plan),
        }

        api_key_env = str(
            (result.provenance.get("api_key_source") or {}).get("name")
            if isinstance(result.provenance.get("api_key_source"), Mapping)
            else ""
        )
        secret_values = [os.getenv(api_key_env)] if api_key_env and os.getenv(api_key_env) else []
        artifacts: list[CapabilityArtifact] = []
        entries: list[dict[str, Any]] = []
        for artifact in _result_artifacts(result.session_id):
            payload = payloads.get(artifact.kind, {})
            encoded = _json_bytes(_redact_secrets(payload, secret_values=secret_values))
            encoded = _redacted_artifact_bytes(encoded, secret_values)
            destination = _artifact_destination(root, artifact.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(encoded)
            _register_materialized_artifact(
                artifact,
                encoded,
                root=root,
                result=result,
                artifacts=artifacts,
                entries=entries,
                source="provider_summary",
            )

        engine_root = (
            root
            / "llm_jailbreak"
            / str(result.session_id)
            / "engine"
        ).resolve()
        engine_files = _safe_engine_files(engine_root)
        for source in engine_files:
            original = source.read_bytes()
            encoded = _redacted_artifact_bytes(original, secret_values)
            if original != encoded:
                source.write_bytes(encoded)
        _refresh_engine_manifest(engine_root, secret_values)
        for source in _safe_engine_files(engine_root):
            encoded = source.read_bytes()
            relative = source.relative_to(root).as_posix()
            engine_relative = source.relative_to(engine_root)
            artifact = CapabilityArtifact(
                path=relative,
                kind=_engine_artifact_kind(engine_relative),
                description=f"Jailbreak engine artifact: {engine_relative.as_posix()}",
                metadata={"schema_version": _SCHEMA_VERSION},
            )
            _register_materialized_artifact(
                artifact,
                encoded,
                root=root,
                result=result,
                artifacts=artifacts,
                entries=entries,
                source="campaign_engine",
            )

        checkpoint_snapshot = _collect_checkpoint_snapshot(
            result,
            root=root,
            secret_values=secret_values,
        )
        if checkpoint_snapshot is not None:
            artifact, encoded = checkpoint_snapshot
            _register_materialized_artifact(
                artifact,
                encoded,
                root=root,
                result=result,
                artifacts=artifacts,
                entries=entries,
                source="checkpoint_snapshot",
            )
            result.report_section.setdefault("checkpoint", {})["snapshot"] = artifact.path
            result.report_section["checkpoint"]["materialized"] = True

        result.artifacts = artifacts
        result.evidence_manifest_entries = entries
        result.report_section["artifact_count"] = len(entries)
        result.report_section["artifacts_materialized"] = True
        return CapabilityArtifactBundle(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            artifacts=list(artifacts),
            manifest_entries=entries,
        )

    def _runner_probe(
        self,
        context: Optional[dict[str, Any]],
    ) -> tuple[bool, Optional[str], Optional[str]]:
        try:
            runner = self._select_runner(context)
        except CoreJailbreakUnavailable as exc:
            return False, None, str(exc)
        return True, _callable_name(runner), None

    def _select_runner(self, context: Optional[dict[str, Any]]) -> Any:
        supplied = (context or {}).get("llm_jailbreak_runner")
        if supplied is not None:
            return _runner_callable(supplied)
        if self.runner is not None:
            return _runner_callable(self.runner)
        return _load_core_entrypoint()

    def _select_transport(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]],
    ) -> Any:
        context = context or {}
        supplied = context.get("llm_jailbreak_transport")
        if supplied is not None:
            return supplied
        if self.transport is not None:
            return self.transport
        factory = context.get("llm_jailbreak_transport_factory") or self.transport_factory
        if factory is None:
            return None
        return _invoke_entrypoint(
            factory,
            {
                "base_url": plan.parameters["base_url"],
                "model": plan.parameters["model"],
                "api_key_env": plan.parameters["api_key_env"],
                "timeout": plan.parameters["timeout"],
            },
        )

    def _require_result(self, result: CapabilityExecutionResult) -> None:
        if result.capability != self.capability_name or result.provider != self.provider_name:
            raise ValueError("execution result does not belong to llm_jailbreak provider")
        if not str(result.session_id or ""):
            raise ValueError("execution result session_id is missing")


def _normalize_action(value: Any) -> str:
    action = str(value or "run").strip().casefold().replace("-", "_")
    return _ACTION_ALIASES.get(action, action)


def _normalize_session_id(value: Any) -> str:
    session_id = str(value or "llm-jailbreak-session").strip()
    if not _SESSION_RE.fullmatch(session_id):
        raise ValueError(
            "session_id must contain only letters, numbers, '.', '_' or '-' and be at most 256 characters"
        )
    return session_id


def _configured_parameter(
    params: Mapping[str, Any],
    name: str,
    fallback: Any,
) -> Any:
    value = params.get(name) if name in params else None
    return fallback if value in (None, "") else value


def _normalize_request_parameters(params: Mapping[str, Any], *, action: str) -> dict[str, Any]:
    if not isinstance(params, Mapping):
        raise TypeError("llm_jailbreak params must be a mapping")
    _reject_inline_api_credentials(params)
    campaign, campaign_path, source_metadata = _load_campaign(params)
    campaign_target = campaign.get("target") if isinstance(campaign.get("target"), Mapping) else {}
    base_url = _normalize_base_url(
        _configured_parameter(params, "base_url", campaign_target.get("base_url", _DEFAULT_BASE_URL))
    )
    model = _normalize_model(
        _configured_parameter(params, "model", campaign_target.get("model", _DEFAULT_MODEL))
    )
    api_key_env = _normalize_api_key_env(
        _configured_parameter(
            params,
            "api_key_env",
            campaign_target.get("api_key_env", _DEFAULT_API_KEY_ENV),
        )
    )
    timeout = _bounded_float(
        _configured_parameter(
            params,
            "timeout",
            campaign_target.get("timeout_seconds", _DEFAULT_TIMEOUT),
        ),
        _DEFAULT_TIMEOUT,
        0.1,
        _MAX_TIMEOUT,
        "timeout",
    )
    max_attempts = _bounded_int(
        _configured_parameter(
            params,
            "max_attempts",
            campaign.get("max_attempts", _DEFAULT_MAX_ATTEMPTS),
        ),
        _DEFAULT_MAX_ATTEMPTS,
        1,
        _MAX_ATTEMPTS,
        "max_attempts",
    )
    max_rounds = _bounded_int(
        _configured_parameter(
            params,
            "max_rounds",
            campaign.get("max_rounds", _DEFAULT_MAX_ROUNDS),
        ),
        _DEFAULT_MAX_ROUNDS,
        1,
        _MAX_ROUNDS,
        "max_rounds",
    )
    resume = _normalize_bool(params.get("resume", action == "resume"), "resume")
    checkpoint_path = _normalize_checkpoint_path(params.get("checkpoint_path"))
    strategies = _normalize_strategies(params.get("strategies", campaign.get("strategies")))
    attack_modes = _normalize_attack_modes(
        _configured_parameter(
            params,
            "attack_modes",
            _configured_parameter(
                params,
                "attack_mode",
                campaign.get("attack_modes", _DEFAULT_ATTACK_MODES),
            ),
        )
    )
    semantic_judge = _normalize_semantic_judge(
        _configured_parameter(
            params,
            "semantic_judge",
            campaign.get("semantic_judge", _DEFAULT_SEMANTIC_JUDGE),
        )
    )
    judge_model = _normalize_optional_model(
        _configured_parameter(
            params,
            "judge_model",
            campaign.get("judge_model", ""),
        ),
        fallback=model if semantic_judge == "model" else "",
        name="judge_model",
    )
    instruction_profile = _normalize_instruction_profile(
        _configured_parameter(
            params,
            "instruction_profile",
            campaign.get("instruction_profile", ""),
        )
    )
    instruction_files = _normalize_instruction_files(
        _configured_parameter(
            params,
            "instruction_files",
            campaign.get("instruction_files", []),
        )
    )
    instruction_contract = _load_instruction_bundle_contract(
        instruction_profile,
        instruction_files,
    )
    if any(
        name in params or name in campaign
        for name in ("instruction_profile", "instruction_files")
    ):
        campaign = dict(campaign)
        if instruction_profile:
            campaign["instruction_profile"] = instruction_profile
        else:
            campaign.pop("instruction_profile", None)
        if instruction_files:
            campaign["instruction_files"] = list(instruction_files)
        else:
            campaign.pop("instruction_files", None)
    options = _json_value(params.get("options") or {})
    if not isinstance(options, dict):
        raise TypeError("options must be a mapping")
    _reject_inline_api_credentials(options)

    instruction_source_refs = list(
        instruction_contract.get("instruction_source_refs") or []
    )
    audit_campaign = _audit_campaign_payload(campaign, instruction_source_refs)
    campaign_sha256 = _sha256_json(audit_campaign)
    campaign_id = _campaign_id(campaign, campaign_sha256)
    metadata = {
        "campaign_id": campaign_id,
        "name": str(campaign.get("name") or campaign_id),
        "sha256": campaign_sha256,
        "source": source_metadata["source"],
        "source_name": source_metadata.get("source_name"),
        "source_size": source_metadata.get("source_size"),
        "prompt_count": _campaign_item_count(campaign),
        "strategy_count": len(strategies),
        "strategies": strategies,
        "attack_modes": attack_modes,
        "semantic_judge": semantic_judge,
        "judge_model": judge_model,
        "instruction_profile": instruction_profile,
        "instruction_files": instruction_source_refs,
        "instruction_bundle_digest": instruction_contract.get(
            "instruction_bundle_digest"
        ),
        "instruction_asset_count": instruction_contract.get(
            "instruction_asset_count"
        ),
        "instruction_bundle_provenance": instruction_contract.get(
            "instruction_bundle_provenance"
        ),
    }
    normalized = _prune(
        {
            "campaign": campaign,
            "campaign_path": campaign_path,
            "campaign_metadata": metadata,
            "base_url": base_url,
            "model": model,
            "api_key_env": api_key_env,
            "timeout": timeout,
            "max_attempts": max_attempts,
            "max_rounds": max_rounds,
            "resume": resume,
            "checkpoint_path": checkpoint_path,
            "strategies": strategies,
            "attack_modes": attack_modes,
            "semantic_judge": semantic_judge,
            "judge_model": judge_model,
            "instruction_profile": instruction_profile,
            "instruction_files": instruction_files,
            **instruction_contract,
            "options": options,
        }
    )
    # Keep all advanced settings explicit in plans, including the intentionally
    # empty judge model used when semantic judging is disabled.
    normalized.update(
        {
            "attack_modes": attack_modes,
            "semantic_judge": semantic_judge,
            "judge_model": judge_model,
        }
    )
    return normalized


def _audit_campaign_payload(
    campaign: Mapping[str, Any],
    instruction_source_refs: Sequence[str],
) -> dict[str, Any]:
    payload = _json_value(campaign)
    if not isinstance(payload, dict):
        return {}
    if instruction_source_refs:
        payload["instruction_files"] = list(instruction_source_refs)
    else:
        payload.pop("instruction_files", None)
    return payload


def _normalize_planned_parameters(parameters: Mapping[str, Any], *, action: str) -> dict[str, Any]:
    if not isinstance(parameters, Mapping):
        raise TypeError("plan parameters must be a mapping")
    campaign = _json_value(parameters.get("campaign"))
    if not isinstance(campaign, dict) or not campaign:
        raise ValueError("campaign must be a non-empty mapping")
    params = {
        "campaign": campaign,
        "base_url": parameters.get("base_url"),
        "model": parameters.get("model"),
        "api_key_env": parameters.get("api_key_env"),
        "timeout": parameters.get("timeout"),
        "max_attempts": parameters.get("max_attempts"),
        "max_rounds": parameters.get("max_rounds"),
        "resume": parameters.get("resume"),
        "checkpoint_path": parameters.get("checkpoint_path"),
        "strategies": parameters.get("strategies"),
        "attack_modes": parameters.get("attack_modes"),
        "semantic_judge": parameters.get("semantic_judge"),
        "judge_model": parameters.get("judge_model"),
        "instruction_profile": parameters.get("instruction_profile"),
        "instruction_files": parameters.get("instruction_files"),
        "options": parameters.get("options"),
    }
    normalized = _normalize_request_parameters(params, action=action)
    advanced_settings = {
        name: normalized[name]
        for name in ("attack_modes", "semantic_judge", "judge_model")
    }
    if parameters.get("campaign_path"):
        normalized["campaign_path"] = str(Path(str(parameters["campaign_path"])).expanduser().resolve())
        normalized["campaign_metadata"].update(
            {
                "source": "path",
                "source_name": Path(normalized["campaign_path"]).name,
                "source_size": parameters.get("campaign_metadata", {}).get("source_size"),
            }
        )
        normalized = _prune(normalized)
        normalized.update(advanced_settings)
    return normalized


def _load_campaign(params: Mapping[str, Any]) -> tuple[dict[str, Any], Optional[str], dict[str, Any]]:
    inline = params.get("campaign")
    path_value = params.get("campaign_path")
    if inline is not None and path_value:
        raise ValueError("provide either campaign or campaign_path, not both")
    if inline is None and not path_value:
        raise ValueError("campaign or campaign_path is required")
    if inline is not None:
        campaign = _json_value(inline)
        if not isinstance(campaign, dict) or not campaign:
            raise ValueError("campaign must be a non-empty mapping")
        _reject_inline_api_credentials(campaign)
        return campaign, None, {"source": "inline"}

    campaign_path = Path(str(path_value)).expanduser().resolve()
    if not campaign_path.is_file():
        raise FileNotFoundError(f"campaign file does not exist: {campaign_path}")
    size = campaign_path.stat().st_size
    if size > _MAX_CAMPAIGN_BYTES:
        raise ValueError(f"campaign file exceeds {_MAX_CAMPAIGN_BYTES} bytes")
    raw = campaign_path.read_bytes()
    campaign = _parse_campaign(raw, campaign_path.suffix.casefold())
    _reject_inline_api_credentials(campaign)
    return (
        campaign,
        str(campaign_path),
        {"source": "path", "source_name": campaign_path.name, "source_size": size},
    )


def _parse_campaign(raw: bytes, suffix: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as json_error:
        if suffix not in {".yaml", ".yml"}:
            raise ValueError(f"campaign file must contain a JSON object: {json_error}") from json_error
        try:
            yaml = importlib.import_module("yaml")
        except ImportError as exc:
            raise ValueError("YAML campaign files require PyYAML") from exc
        payload = yaml.safe_load(raw.decode("utf-8-sig"))
    value = _json_value(payload)
    if not isinstance(value, dict) or not value:
        raise ValueError("campaign file must contain a non-empty object")
    return value


def _safe_target(target: TargetIdentity, parameters: Mapping[str, Any]) -> TargetIdentity:
    metadata = _redact_secrets(dict(getattr(target, "metadata", {}) or {}))
    metadata.update(
        {
            "model": parameters["model"],
            "base_url": parameters["base_url"],
            "campaign_id": parameters["campaign_metadata"]["campaign_id"],
        }
    )
    return TargetIdentity(
        kind=str(getattr(target, "kind", None) or "llm_endpoint"),
        path=getattr(target, "path", None),
        pid=getattr(target, "pid", None),
        sha256=getattr(target, "sha256", None),
        display_name=str(getattr(target, "display_name", None) or parameters["model"]),
        metadata=metadata,
    )


def _precondition_payload(
    target: TargetIdentity,
    parameters: Mapping[str, Any],
    action: str,
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "action": action,
        "target_identity": _target_payload(target),
        "parameters": _json_value(parameters),
    }


def _before_snapshot(
    target: TargetIdentity,
    parameters: Mapping[str, Any],
    precondition_hash: str,
) -> dict[str, Any]:
    return {
        "state": "planned",
        "target_identity": _target_payload(target),
        "campaign": _json_value(parameters["campaign_metadata"]),
        "model": parameters["model"],
        "base_url": parameters["base_url"],
        "execution": _execution_settings(parameters),
        "precondition_hash": precondition_hash,
        "api_key_value_persisted": False,
    }


def _planned_rollback(parameters: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "supported": True,
        "status": "planned",
        "mode": "local_campaign_state_cleanup",
        "campaign_id": parameters["campaign_metadata"]["campaign_id"],
        "local_state_restorable": True,
        "remote_requests_reversible": False,
    }


def _execution_settings(parameters: Mapping[str, Any]) -> dict[str, Any]:
    settings = {
        "base_url": parameters["base_url"],
        "model": parameters["model"],
        "api_key_env": parameters["api_key_env"],
        "timeout": parameters["timeout"],
        "max_attempts": parameters["max_attempts"],
        "max_rounds": parameters["max_rounds"],
        "resume": parameters["resume"],
        "checkpoint_path": parameters.get("checkpoint_path"),
        "strategies": list(parameters.get("strategies") or []),
        "attack_modes": list(parameters.get("attack_modes") or _DEFAULT_ATTACK_MODES),
        "semantic_judge": parameters.get("semantic_judge", _DEFAULT_SEMANTIC_JUDGE),
        "judge_model": parameters.get("judge_model", ""),
        "options": _json_value(parameters.get("options") or {}),
        "api_key_value_persisted": False,
    }
    if parameters.get("instruction_profile"):
        settings["instruction_profile"] = parameters["instruction_profile"]
    if parameters.get("instruction_files"):
        settings["instruction_files"] = list(parameters["instruction_files"])
    settings.update(_campaign_execution_contract(parameters))
    return settings


def _checkpoint_metadata(parameters: Mapping[str, Any]) -> dict[str, Any]:
    checkpoint_path = parameters.get("checkpoint_path")
    return _prune(
        {
            "path": str(checkpoint_path) if checkpoint_path else None,
            "configured": bool(checkpoint_path),
            "resume_requested": bool(parameters.get("resume")),
        }
    )


def _runner_invocation(
    plan: CapabilityPlan,
    *,
    transport: Any,
    context: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    invocation = {
        "campaign": _json_value(plan.parameters["campaign"]),
        "campaign_path": plan.parameters.get("campaign_path"),
        "campaign_id": plan.parameters["campaign_metadata"]["campaign_id"],
        "base_url": plan.parameters["base_url"],
        "model": plan.parameters["model"],
        "api_key_env": plan.parameters["api_key_env"],
        "timeout": plan.parameters["timeout"],
        "max_attempts": plan.parameters["max_attempts"],
        "max_rounds": plan.parameters["max_rounds"],
        "resume": plan.parameters["resume"],
        "checkpoint_path": plan.parameters.get("checkpoint_path"),
        "strategies": list(plan.parameters.get("strategies") or []),
        "attack_modes": list(
            plan.parameters.get("attack_modes") or _DEFAULT_ATTACK_MODES
        ),
        "semantic_judge": plan.parameters.get(
            "semantic_judge", _DEFAULT_SEMANTIC_JUDGE
        ),
        "judge_model": plan.parameters.get("judge_model", ""),
        "options": _json_value(plan.parameters.get("options") or {}),
        "session_id": plan.session_id,
        "target_identity": _target_payload(plan.target),
    }
    if plan.parameters.get("instruction_profile"):
        invocation["instruction_profile"] = plan.parameters["instruction_profile"]
    if plan.parameters.get("instruction_files"):
        invocation["instruction_files"] = list(plan.parameters["instruction_files"])
    if plan.parameters.get("instruction_bundle_snapshot"):
        invocation["instruction_bundle"] = _json_value(
            plan.parameters["instruction_bundle_snapshot"]
        )
    context_out = (context or {}).get("out_dir")
    if context_out:
        root = Path(str(context_out)).expanduser().resolve()
        invocation["out_dir"] = str(
            root / "llm_jailbreak" / str(plan.session_id) / "engine"
        )
    if transport is not None:
        invocation["transport"] = transport
    return invocation


def _load_core_entrypoint() -> Callable[..., Any]:
    import_errors: list[str] = []
    for module_name in _CORE_MODULES:
        try:
            module = importlib.import_module(module_name)
        except (ImportError, ModuleNotFoundError) as exc:
            import_errors.append(f"{module_name}: {exc}")
            continue
        for name in _CORE_FUNCTIONS:
            candidate = getattr(module, name, None)
            if callable(candidate):
                return candidate
        for name in _CORE_RUNNER_CLASSES:
            candidate = getattr(module, name, None)
            if not callable(candidate):
                continue
            try:
                instance = candidate()
            except TypeError:
                continue
            try:
                return _runner_callable(instance)
            except TypeError:
                continue
    detail = "; ".join(import_errors[-2:])
    raise CoreJailbreakUnavailable(
        "reverse_analyzer.llm_jailbreak does not expose execute_campaign, run_campaign, "
        f"JailbreakCampaignRunner, or CampaignRunner{': ' + detail if detail else ''}"
    )


def _runner_callable(value: Any) -> Callable[..., Any]:
    if callable(value):
        return value
    for name in ("run_campaign", "run", "execute"):
        candidate = getattr(value, name, None)
        if callable(candidate):
            return candidate
    raise TypeError("jailbreak runner must be callable or expose run_campaign(), run(), or execute()")


def _invoke_entrypoint(entrypoint: Any, payload: Mapping[str, Any]) -> Any:
    function = _runner_callable(entrypoint)
    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return function(dict(payload))
    parameters = signature.parameters
    if any(item.kind == inspect.Parameter.VAR_KEYWORD for item in parameters.values()):
        return function(**dict(payload))
    accepted = {
        name: payload[name]
        for name, item in parameters.items()
        if name in payload
        and item.kind in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}
    }
    required = [
        item
        for item in parameters.values()
        if item.default is inspect.Parameter.empty
        and item.kind in {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD}
    ]
    if len(required) == 1 and required[0].name not in accepted:
        return function(dict(payload))
    missing = [item.name for item in required if item.name not in accepted]
    if missing:
        raise TypeError(f"entrypoint requires unsupported parameters: {', '.join(missing)}")
    return function(**accepted)


def _result_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return _json_value(value)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        mapped = value.to_dict()
        if isinstance(mapped, Mapping):
            return _json_value(mapped)
    if is_dataclass(value):
        return _json_value(asdict(value))
    raise TypeError("jailbreak core runner must return a mapping or dataclass-like result")


def _execution_status(result: Mapping[str, Any]) -> str:
    explicit = str(result.get("status") or "").strip().casefold()
    if explicit in {"unavailable", "dependency_missing"}:
        return "unavailable"
    if explicit in {"failed", "error", "cancelled"} or result.get("error"):
        return "failed"
    return "ok"


def _normalized_attempts(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = result.get("attempts") or result.get("records") or result.get("trials") or []
    if isinstance(raw, Mapping):
        raw = list(raw.values())
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return []
    attempts: list[dict[str, Any]] = []
    for index, item in enumerate(raw, start=1):
        if isinstance(item, Mapping):
            attempt = _json_value(item)
        else:
            attempt = {"value": _json_value(item)}
        attempt.setdefault("attempt", index)
        attempts.append(attempt)
    return attempts


def _execution_summary(
    plan: CapabilityPlan,
    result: Mapping[str, Any],
    attempts: Sequence[Mapping[str, Any]],
    status: str,
) -> dict[str, Any]:
    best = result.get("best_attempt") if isinstance(result.get("best_attempt"), Mapping) else {}
    strategy_value = result.get("strategy") or best.get("strategy")
    if isinstance(strategy_value, Mapping):
        strategy_value = strategy_value.get("name") or strategy_value.get("id")
    if not strategy_value:
        strategy_value = next(
            (item.get("strategy") for item in reversed(attempts) if item.get("strategy")),
            None,
        )
    if not strategy_value:
        configured = list(plan.parameters.get("strategies") or [])
        strategy_value = configured[0] if len(configured) == 1 else "adaptive"

    success = bool(
        result.get("success")
        or result.get("jailbroken")
        or result.get("breakthrough")
        or best.get("success")
        or any(
            item.get("success") or item.get("jailbroken") or item.get("breakthrough")
            for item in attempts
        )
    )
    score_candidates = [
        result.get("score"),
        result.get("best_score"),
        best.get("score"),
        *[item.get("score") for item in attempts],
    ]
    score = max((_safe_float(value) for value in score_candidates if value is not None), default=0.0)
    attempt_count = _safe_int(result.get("attempt_count"), len(attempts))
    latency_ms = _safe_float(result.get("latency_ms"))
    result_summary = result.get("summary")
    if latency_ms == 0.0 and isinstance(result_summary, Mapping):
        latency_ms = 1000.0 * _safe_float(result_summary.get("latency_seconds"))
    if latency_ms == 0.0:
        for item in attempts:
            attempt_latency = _safe_float(item.get("latency_ms"))
            response = item.get("response")
            if attempt_latency == 0.0 and isinstance(response, Mapping):
                attempt_latency = 1000.0 * _safe_float(response.get("latency_seconds"))
            latency_ms += attempt_latency
    summary = {
        "strategy": str(strategy_value),
        "attack_modes": list(
            plan.parameters.get("attack_modes") or _DEFAULT_ATTACK_MODES
        ),
        "semantic_judge": plan.parameters.get(
            "semantic_judge", _DEFAULT_SEMANTIC_JUDGE
        ),
        "judge_model": plan.parameters.get("judge_model", ""),
        "success": success,
        "score": score,
        "attempt_count": max(attempt_count, len(attempts)),
        "latency_ms": max(0.0, latency_ms),
        "model": plan.parameters["model"],
        "base_url": plan.parameters["base_url"],
        "campaign_id": plan.parameters["campaign_metadata"]["campaign_id"],
        "execution_status": status,
    }
    if plan.parameters.get("instruction_profile"):
        summary["instruction_profile"] = plan.parameters["instruction_profile"]
    if plan.parameters.get("instruction_files"):
        summary["instruction_files"] = list(plan.parameters["instruction_files"])
    summary.update(_campaign_execution_contract(plan.parameters))
    for key, value in _instruction_bundle_summary(result, attempts).items():
        summary.setdefault(key, value)
    return summary


def _instruction_bundle_summary(
    result: Mapping[str, Any],
    attempts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Extract the compact instruction asset identity emitted by the core engine."""

    candidates: list[Mapping[str, Any]] = []

    def append_candidates(value: Any) -> None:
        if not isinstance(value, Mapping):
            return
        candidates.append(value)
        for key in ("instruction_asset", "instruction_bundle"):
            nested = value.get(key)
            if isinstance(nested, Mapping):
                candidates.append(nested)

    append_candidates(result)
    append_candidates(result.get("summary"))
    best = result.get("best_attempt")
    append_candidates(best)
    if isinstance(best, Mapping):
        append_candidates(best.get("metadata"))
    for attempt in reversed(attempts):
        append_candidates(attempt)
        append_candidates(attempt.get("metadata"))

    extracted: dict[str, Any] = {}
    for candidate in candidates:
        if "instruction_bundle_digest" not in extracted:
            digest = candidate.get("instruction_bundle_digest")
            if digest in (None, ""):
                digest = candidate.get("bundle_digest", candidate.get("digest"))
            normalized_digest = str(digest or "").strip().casefold()
            if re.fullmatch(r"[0-9a-f]{64}", normalized_digest):
                extracted["instruction_bundle_digest"] = normalized_digest

        if "instruction_asset_count" not in extracted:
            raw_count = candidate.get(
                "instruction_asset_count",
                candidate.get("asset_count"),
            )
            if raw_count is None:
                assets = candidate.get("assets")
                if isinstance(assets, Sequence) and not isinstance(
                    assets, (str, bytes, bytearray)
                ):
                    raw_count = len(assets)
            count = _safe_int(raw_count, -1)
            if count >= 0:
                extracted["instruction_asset_count"] = count

        if "instruction_bundle_provenance" not in extracted:
            provenance = candidate.get(
                "instruction_bundle_provenance",
                candidate.get("bundle_provenance"),
            )
            if isinstance(provenance, Mapping):
                extracted["instruction_bundle_provenance"] = _json_value(
                    provenance
                )

        if {
            "instruction_bundle_digest",
            "instruction_asset_count",
            "instruction_bundle_provenance",
        }.issubset(extracted):
            break
    return extracted


def _result_artifacts(session_id: str) -> list[CapabilityArtifact]:
    root = f"llm_jailbreak/{session_id}"
    return [
        CapabilityArtifact(
            path=f"{root}/{filename}",
            kind=kind,
            description=description,
            metadata={"materialized": False, "schema_version": _SCHEMA_VERSION},
        )
        for filename, kind, description in _ARTIFACT_SPECS
    ]


def _manifest_entry(
    artifact: CapabilityArtifact,
    plan: CapabilityPlan,
    *,
    status: str,
    materialized: bool,
) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "role": artifact.kind,
        "tool": "llm_jailbreak",
        "provider": plan.provider,
        "session_id": plan.session_id,
        "status": status,
        "target_identity": _target_payload(plan.target),
        "precondition_hash": plan.precondition_hash,
        "materialized": materialized,
        **_campaign_execution_contract(plan.parameters),
    }


def _fallback_payloads(result: CapabilityExecutionResult) -> dict[str, Any]:
    summary = {
        key: result.report_section.get(key)
        for key in (
            "strategy",
            "attack_modes",
            "semantic_judge",
            "judge_model",
            "success",
            "score",
            "attempt_count",
            "latency_ms",
            "model",
            "base_url",
            "campaign_id",
        )
    }
    for key in (
        "instruction_profile",
        "instruction_files",
        "instruction_bundle_digest",
        "instruction_asset_count",
        "instruction_bundle_provenance",
    ):
        if result.report_section.get(key):
            summary[key] = _json_value(result.report_section[key])
    return {
        "llm-jailbreak-campaign": {
            "schema_version": _SCHEMA_VERSION,
            "session_id": result.session_id,
            "target_identity": _target_payload(result.target),
            "campaign_id": summary["campaign_id"],
            "metadata_only": True,
        },
        "llm-jailbreak-result": {
            "schema_version": _SCHEMA_VERSION,
            "session_id": result.session_id,
            "summary": summary,
            "status": result.status,
        },
        "llm-jailbreak-attempts": {
            "schema_version": _SCHEMA_VERSION,
            "session_id": result.session_id,
            "attempt_count": summary["attempt_count"],
            "attempts": [],
            "details_available": False,
        },
        "llm-jailbreak-rollback": {
            "schema_version": _SCHEMA_VERSION,
            "session_id": result.session_id,
            **_json_value(result.rollback_plan),
        },
    }


def _safe_engine_files(engine_root: Path) -> list[Path]:
    """Return regular engine artifacts without following links outside the session."""

    root = engine_root.expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        return []
    files: list[Path] = []
    for candidate in root.rglob("*"):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        files.append(resolved)
    return sorted(set(files), key=lambda item: item.relative_to(root).as_posix())


def _redacted_artifact_bytes(
    content: bytes,
    secret_values: Sequence[str] = (),
) -> bytes:
    """Redact credentials from UTF-8 artifacts while leaving opaque bytes intact."""

    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        redacted = content
        for secret in secret_values:
            if secret:
                redacted = redacted.replace(secret.encode("utf-8"), b"[REDACTED]")
        return redacted
    return _redact_string(text, secret_values).encode("utf-8")


def _refresh_engine_manifest(
    engine_root: Path,
    secret_values: Sequence[str] = (),
) -> None:
    """Rebuild engine checksums after persisted responses have been redacted."""

    root = engine_root.expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        return
    manifest_path = root / "manifest.json"
    manifest: dict[str, Any] = {}
    if manifest_path.is_file() and not manifest_path.is_symlink():
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            loaded = {}
        if isinstance(loaded, Mapping):
            manifest = _redact_secrets(loaded, secret_values=secret_values)

    entries: list[dict[str, Any]] = []
    for path in _safe_engine_files(root):
        if path == manifest_path:
            continue
        encoded = path.read_bytes()
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }
        )
    manifest.update(
        {
            "schema_version": manifest.get("schema_version", _SCHEMA_VERSION),
            "artifact_count": len(entries),
            "artifacts": entries,
        }
    )
    manifest_path.write_bytes(
        _redacted_artifact_bytes(_json_bytes(manifest), secret_values)
    )


def _engine_artifact_kind(relative_path: Path) -> str:
    normalized = relative_path.as_posix()
    if relative_path.parts and relative_path.parts[0] == "prompts":
        return "llm-jailbreak-prompt"
    if relative_path.parts and relative_path.parts[0] == "responses":
        return "llm-jailbreak-response"
    if relative_path.parts and relative_path.parts[0] == "instructions":
        return "llm-jailbreak-instruction-asset"
    if normalized in _ENGINE_ARTIFACT_KINDS:
        return _ENGINE_ARTIFACT_KINDS[normalized]
    return "llm-jailbreak-engine-artifact"


def _collect_checkpoint_snapshot(
    result: CapabilityExecutionResult,
    *,
    root: Path,
    secret_values: Sequence[str] = (),
) -> Optional[tuple[CapabilityArtifact, bytes]]:
    checkpoint = result.provenance.get("checkpoint")
    if not isinstance(checkpoint, Mapping) or not checkpoint.get("path"):
        return None
    source = Path(str(checkpoint["path"])).expanduser().resolve()
    if source.is_symlink() or not source.is_file():
        return None

    original = source.read_bytes()
    encoded = _redacted_artifact_bytes(original, secret_values)
    if original != encoded:
        source.write_bytes(encoded)
    relative = f"llm_jailbreak/{result.session_id}/checkpoint.json"
    destination = _artifact_destination(root, relative)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination != source:
        destination.write_bytes(encoded)
    artifact = CapabilityArtifact(
        path=relative,
        kind="llm-jailbreak-checkpoint",
        description="Session-fixed snapshot of the resumable jailbreak checkpoint",
        metadata={
            "schema_version": _SCHEMA_VERSION,
            "checkpoint_configured": True,
        },
    )
    return artifact, encoded


def _register_materialized_artifact(
    artifact: CapabilityArtifact,
    encoded: bytes,
    *,
    root: Path,
    result: CapabilityExecutionResult,
    artifacts: list[CapabilityArtifact],
    entries: list[dict[str, Any]],
    source: str,
) -> None:
    digest = hashlib.sha256(encoded).hexdigest()
    artifact.metadata.update(
        {
            "materialized": True,
            "sha256": digest,
            "size": len(encoded),
            "collection_root": str(root),
            "source": source,
        }
    )
    artifacts.append(artifact)
    entries.append(
        {
            "path": artifact.path,
            "kind": artifact.kind,
            "role": artifact.kind,
            "tool": "llm_jailbreak",
            "provider": result.provider,
            "session_id": result.session_id,
            "status": result.status,
            "target_identity": _target_payload(result.target),
            "precondition_hash": result.provenance.get("precondition_hash"),
            "materialized": True,
            "sha256": digest,
            "size": len(encoded),
            "source": source,
            **_campaign_execution_contract(result.report_section),
        }
    )


def _artifact_destination(root: Path, relative_path: str) -> Path:
    relative = Path(str(relative_path).replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"artifact path must remain relative: {relative_path!r}")
    destination = (root / relative).resolve()
    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"artifact path escapes collection root: {relative_path!r}") from exc
    return destination


def _normalize_base_url(value: Any) -> str:
    text = str(value or "").strip()
    parts = urlsplit(text)
    if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
        raise ValueError("base_url must be an absolute HTTP(S) URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("base_url must not contain credentials, query parameters, or fragments")
    host = parts.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parts.port is not None:
        netloc = f"{host}:{parts.port}"
    path = parts.path.rstrip("/") or ""
    return urlunsplit((parts.scheme.casefold(), netloc, path, "", ""))


def _normalize_checkpoint_path(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    if isinstance(value, (bytes, bytearray, Mapping, Sequence)) and not isinstance(value, str):
        raise TypeError("checkpoint_path must be a filesystem path")
    text = str(value).strip()
    if not text or "\x00" in text:
        raise ValueError("checkpoint_path must be a non-empty filesystem path")
    path = Path(text).expanduser().resolve()
    if path.exists() and not path.is_file():
        raise ValueError(f"checkpoint_path must identify a file: {path}")
    return str(path)


def _normalize_model(value: Any) -> str:
    model = str(value or "").strip()
    if not model or len(model) > 256 or any(char in model for char in "\r\n\0"):
        raise ValueError("model must contain 1-256 printable characters")
    return model


def _normalize_optional_model(value: Any, *, fallback: str, name: str) -> str:
    if value in (None, ""):
        value = fallback
    if value in (None, ""):
        return ""
    try:
        return _normalize_model(value)
    except ValueError as exc:
        raise ValueError(f"{name} must contain 1-256 printable characters") from exc


def _normalize_api_key_env(value: Any) -> str:
    name = str(value or "").strip()
    if not _ENV_NAME_RE.fullmatch(name):
        raise ValueError("api_key_env must be a valid environment variable name")
    return name


def _normalize_attack_modes(value: Any) -> list[str]:
    if isinstance(value, str):
        values: Sequence[Any] = (value,)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        values = value
    else:
        raise TypeError("attack_modes must be a sequence or comma-separated string")

    raw: list[str] = []
    for item in values:
        if isinstance(item, Mapping):
            item = item.get("name") or item.get("id")
        raw.extend(part.strip().casefold() for part in str(item or "").split(","))
    modes = _dedupe(item for item in raw if item)
    if not modes:
        raise ValueError("attack_modes must contain at least one mode")
    unsupported = [item for item in modes if item not in _SUPPORTED_ATTACK_MODES]
    if unsupported:
        raise ValueError(
            "attack_modes contains unsupported values: " + ", ".join(unsupported)
        )
    return modes


def _normalize_semantic_judge(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("semantic_judge must be a string")
    normalized = value.strip().casefold()
    if normalized not in _SUPPORTED_SEMANTIC_JUDGES:
        raise ValueError(
            "semantic_judge must be one of: "
            + ", ".join(_SUPPORTED_SEMANTIC_JUDGES)
        )
    return normalized


def _normalize_instruction_profile(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("instruction_profile must be a string")
    profile = value.strip()
    if not profile:
        return ""
    from reverse_analyzer.llm_jailbreak.instruction_assets import (
        resolve_instruction_profile,
    )

    return resolve_instruction_profile(profile)


def _normalize_instruction_files(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        raise TypeError("instruction_files must be an array of strings")
    files: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"instruction_files[{index}] must be a non-empty string"
            )
        files.append(item.strip())
    duplicates = sorted({item for item in files if files.count(item) > 1})
    if duplicates:
        raise ValueError(
            "instruction_files contains duplicates: " + ", ".join(duplicates)
        )
    for index, path in enumerate(files):
        if Path(path).suffix.casefold() not in {".md", ".markdown"}:
            raise ValueError(
                f"instruction_files[{index}] must be a Markdown file"
            )
    return files


def _load_instruction_bundle_contract(
    profile: str,
    files: Sequence[str],
) -> dict[str, Any]:
    """Load instruction assets during planning and persist only their identity."""

    if not profile and not files:
        return {}
    from reverse_analyzer.llm_jailbreak.instruction_assets import (
        load_instruction_bundle,
    )

    bundle = load_instruction_bundle(profile, files)
    source_refs = [
        asset.source
        for asset in bundle.assets
        if asset.provenance.get("kind") == "custom-markdown"
    ]
    return {
        "instruction_bundle_digest": bundle.digest,
        "instruction_asset_count": len(bundle.assets),
        "instruction_bundle_provenance": _json_value(bundle.provenance),
        "instruction_source_refs": source_refs,
        "instruction_bundle_snapshot": _json_value(bundle.to_dict()),
    }


def _campaign_execution_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the cross-surface campaign fields used by audit consumers."""

    attack_modes = value.get("attack_modes")
    if isinstance(attack_modes, str):
        attack_modes = [
            item.strip() for item in attack_modes.split(",") if item.strip()
        ]
    elif isinstance(attack_modes, Sequence) and not isinstance(
        attack_modes, (str, bytes, bytearray)
    ):
        attack_modes = list(attack_modes)
    else:
        attack_modes = []

    provenance = value.get("instruction_bundle_provenance")
    source_refs = value.get("instruction_source_refs")
    if not isinstance(source_refs, Sequence) or isinstance(
        source_refs, (str, bytes, bytearray)
    ):
        source_refs = value.get("instruction_files") or []
    return _prune(
        {
            "attack_modes": _json_value(attack_modes),
            "semantic_judge": value.get("semantic_judge"),
            "judge_model": value.get("judge_model"),
            "instruction_profile": value.get("instruction_profile"),
            "instruction_files": _json_value(source_refs),
            "instruction_bundle_digest": value.get("instruction_bundle_digest"),
            "instruction_asset_count": value.get("instruction_asset_count"),
            "instruction_bundle_provenance": (
                _json_value(provenance)
                if isinstance(provenance, Mapping)
                else None
            ),
        }
    )


def _normalize_strategies(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        raw = [item.strip() for item in value.split(",")]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        raw = []
        for item in value:
            if isinstance(item, Mapping):
                item = item.get("name") or item.get("id")
            raw.append(str(item or "").strip())
    else:
        raise TypeError("strategies must be a sequence or comma-separated string")
    strategies = _dedupe(item for item in raw if item)
    if len(strategies) > 256 or any(len(item) > 128 for item in strategies):
        raise ValueError("strategies contains too many or overly long names")
    return strategies


def _normalize_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return False
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    raise ValueError(f"{name} must be a boolean")


def _bounded_int(value: Any, default: int, minimum: int, maximum: int, name: str) -> int:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if normalized < minimum or normalized > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return normalized


def _bounded_float(value: Any, default: float, minimum: float, maximum: float, name: str) -> float:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    try:
        normalized = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc
    if normalized < minimum or normalized > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return normalized


def _campaign_id(campaign: Mapping[str, Any], digest: str) -> str:
    value = str(campaign.get("campaign_id") or campaign.get("id") or campaign.get("name") or "").strip()
    if not value:
        value = f"campaign-{digest[:12]}"
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.")
    return (safe or f"campaign-{digest[:12]}")[:128]


def _campaign_item_count(campaign: Mapping[str, Any]) -> int:
    for key in ("attempts", "prompts", "attacks", "seeds", "cases", "goals"):
        value = campaign.get(key)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return len(value)
    return 0


def _target_payload(target: TargetIdentity) -> dict[str, Any]:
    return _prune(_redact_secrets(target.to_dict()))


def _api_key_values(parameters: Mapping[str, Any]) -> list[str]:
    env_name = str(parameters.get("api_key_env") or "")
    value = os.getenv(env_name) if env_name else None
    return [value] if value else []


def _reject_inline_api_credentials(value: Any, path: str = "params") -> None:
    paths = _secret_key_paths(value, path=path)
    if paths:
        raise ValueError(
            "API credentials must be supplied through api_key_env, not inline: " + ", ".join(paths)
        )


def _secret_key_paths(value: Any, *, path: str = "root") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            child = f"{path}.{key_text}"
            if _is_secret_key(key_text):
                found.append(child)
            else:
                found.extend(_secret_key_paths(item, path=child))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            found.extend(_secret_key_paths(item, path=f"{path}[{index}]"))
    return found


def _is_secret_key(value: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", value.casefold())
    return compact in _SECRET_KEYS


def _redact_secrets(value: Any, *, secret_values: Sequence[str] = ()) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]"
                if _is_secret_key(str(key))
                else _redact_secrets(item, secret_values=secret_values)
            )
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact_secrets(item, secret_values=secret_values) for item in value]
    if isinstance(value, str):
        return _redact_string(value, secret_values)
    return _json_value(value)


def _redact_string(value: str, secret_values: Sequence[str] = ()) -> str:
    text = value
    for secret in secret_values:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _OPENAI_KEY_RE.sub("[REDACTED]", text)
    return _INLINE_KEY_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", text)


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    if is_dataclass(value):
        return _json_value(asdict(value))
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _json_value(value.to_dict())
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (bytes, bytearray)):
        return {"encoding": "hex", "value": bytes(value).hex()}
    if isinstance(value, Path):
        return str(value)
    return str(value)


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            _json_value(value),
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _callable_name(value: Any) -> str:
    return str(
        getattr(value, "__qualname__", None)
        or getattr(value, "__name__", None)
        or type(value).__name__
    )


def _safe_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _dedupe(values: Sequence[Any] | Any) -> list[Any]:
    result: list[Any] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _prune(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _prune(item)
            for key, item in value.items()
            if item not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [_prune(item) for item in value if item not in (None, "", [], {})]
    return value


__all__ = ["CoreJailbreakUnavailable", "LLMJailbreakProvider"]
