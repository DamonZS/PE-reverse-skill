"""Deterministic, offline-only target-control simulation provider.

The provider consumes observations supplied in the capability request.  It has
no process, input-device, injection, network, or live-capture backend.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Optional

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


ALGORITHM_VERSION = "target-control-offline-v1"
AUDIT_SCHEMA_VERSION = 1
MAX_FRAMES = 256
MAX_CANDIDATES_PER_FRAME = 512
MAX_TOTAL_CANDIDATES = 4096
MAX_TRAJECTORY_STEPS = 64
MAX_PARAMETER_JSON_BYTES = 4 * 1024 * 1024

_SUPPORTED_ACTIONS = {"simulate"}
_MAX_FOV = 180.0
_MAX_COORDINATE = 360.0
_MAX_DISTANCE = 1_000_000.0
_MAX_TIMESTAMP_MS = 10**15
_MAX_SESSION_LENGTH = 128
_MAX_IDENTITY_LENGTH = 256
_FLOAT_DIGITS = 12
_SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")

_CONFIG_KEYS = {
    "max_fov",
    "fov_limit",
    "max_distance",
    "distance_limit",
    "min_confidence",
    "confidence_threshold",
    "weights",
    "fov_weight",
    "distance_weight",
    "confidence_weight",
    "smoothing_factor",
    "smoothing",
    "trajectory_steps",
    "smoothing_steps",
    "max_step",
    "max_step_size",
    "trigger",
    "trigger_enabled",
    "trigger_radius",
    "trigger_fov",
    "trigger_min_confidence",
    "recoil_compensation",
    "recoil_enabled",
    "recoil_scale_x",
    "recoil_scale_y",
    "recoil_yaw_scale",
    "recoil_pitch_scale",
    "require_visible",
    "require_alive",
    "require_hostile",
    "initial_control",
    "initial_x",
    "initial_y",
}


def _offline_boundary() -> dict[str, Any]:
    return {
        "mode": "offline_deterministic_simulation",
        "mocked": False,
        "dependency": {"required": False, "status": "not_required"},
        "observations_source": "request_parameters_only",
        "process_access": False,
        "injection": False,
        "live_capture": False,
        "input_device_access": False,
        "input_emission": False,
        "network_access": False,
        "live_automated_target_control": False,
    }


@dataclass(frozen=True)
class SimulationConfig:
    """Finite numerical controls for the pure simulation algorithm."""

    max_fov: float = 30.0
    max_distance: float = 1000.0
    min_confidence: float = 0.5
    fov_weight: float = 0.5
    distance_weight: float = 0.2
    confidence_weight: float = 0.3
    smoothing_factor: float = 0.35
    trajectory_steps: int = 4
    max_step: float = 30.0
    trigger_enabled: bool = True
    trigger_radius: float = 1.0
    trigger_min_confidence: float = 0.8
    recoil_enabled: bool = True
    recoil_scale_x: float = 1.0
    recoil_scale_y: float = 1.0
    require_visible: bool = True
    require_alive: bool = True
    require_hostile: bool = True
    initial_x: float = 0.0
    initial_y: float = 0.0

    @classmethod
    def from_mapping(cls, value: Optional[Mapping[str, Any]] = None) -> "SimulationConfig":
        raw = dict(value or {})
        unknown = sorted(set(raw) - _CONFIG_KEYS)
        if unknown:
            raise ValueError("unknown simulation config fields: " + ", ".join(unknown))

        defaults = cls()
        weights = _nested_config(raw.get("weights"), "weights", {"fov", "distance", "confidence"})
        trigger = _nested_toggle(
            raw.get("trigger"),
            "trigger",
            {"enabled", "radius", "fov", "min_confidence", "confidence"},
        )
        recoil = _nested_toggle(
            raw.get("recoil_compensation"),
            "recoil_compensation",
            {"enabled", "scale_x", "scale_y", "yaw_scale", "pitch_scale"},
        )

        initial = raw.get("initial_control")
        initial_x: Any = defaults.initial_x
        initial_y: Any = defaults.initial_y
        initial_values: dict[str, Any] = {}
        if initial is not None:
            initial_x, initial_y = _pair(initial, "initial_control", limit=_MAX_COORDINATE)
            initial_values = {"initial_x": initial_x, "initial_y": initial_y}

        config = cls(
            max_fov=_bounded_float(
                _coalesced((raw, ("max_fov", "fov_limit")), default=defaults.max_fov, name="max_fov"),
                "max_fov",
                minimum=0.001,
                maximum=_MAX_FOV,
            ),
            max_distance=_bounded_float(
                _coalesced(
                    (raw, ("max_distance", "distance_limit")),
                    default=defaults.max_distance,
                    name="max_distance",
                ),
                "max_distance",
                minimum=0.001,
                maximum=_MAX_DISTANCE,
            ),
            min_confidence=_bounded_float(
                _coalesced(
                    (raw, ("min_confidence", "confidence_threshold")),
                    default=defaults.min_confidence,
                    name="min_confidence",
                ),
                "min_confidence",
                minimum=0.0,
                maximum=1.0,
            ),
            fov_weight=_bounded_float(
                _coalesced(
                    (raw, ("fov_weight",)),
                    (weights, ("fov",)),
                    default=defaults.fov_weight,
                    name="fov_weight",
                ),
                "fov_weight",
                minimum=0.0,
                maximum=1.0,
            ),
            distance_weight=_bounded_float(
                _coalesced(
                    (raw, ("distance_weight",)),
                    (weights, ("distance",)),
                    default=defaults.distance_weight,
                    name="distance_weight",
                ),
                "distance_weight",
                minimum=0.0,
                maximum=1.0,
            ),
            confidence_weight=_bounded_float(
                _coalesced(
                    (raw, ("confidence_weight",)),
                    (weights, ("confidence",)),
                    default=defaults.confidence_weight,
                    name="confidence_weight",
                ),
                "confidence_weight",
                minimum=0.0,
                maximum=1.0,
            ),
            smoothing_factor=_bounded_float(
                _coalesced(
                    (raw, ("smoothing_factor", "smoothing")),
                    default=defaults.smoothing_factor,
                    name="smoothing_factor",
                ),
                "smoothing_factor",
                minimum=0.001,
                maximum=1.0,
            ),
            trajectory_steps=_bounded_int(
                _coalesced(
                    (raw, ("trajectory_steps", "smoothing_steps")),
                    default=defaults.trajectory_steps,
                    name="trajectory_steps",
                ),
                "trajectory_steps",
                minimum=1,
                maximum=MAX_TRAJECTORY_STEPS,
            ),
            max_step=_bounded_float(
                _coalesced(
                    (raw, ("max_step", "max_step_size")),
                    default=defaults.max_step,
                    name="max_step",
                ),
                "max_step",
                minimum=0.001,
                maximum=_MAX_COORDINATE,
            ),
            trigger_enabled=_strict_bool(
                _coalesced(
                    (raw, ("trigger_enabled",)),
                    (trigger, ("enabled",)),
                    default=defaults.trigger_enabled,
                    name="trigger_enabled",
                ),
                "trigger_enabled",
            ),
            trigger_radius=_bounded_float(
                _coalesced(
                    (raw, ("trigger_radius", "trigger_fov")),
                    (trigger, ("radius", "fov")),
                    default=defaults.trigger_radius,
                    name="trigger_radius",
                ),
                "trigger_radius",
                minimum=0.0,
                maximum=_MAX_FOV,
            ),
            trigger_min_confidence=_bounded_float(
                _coalesced(
                    (raw, ("trigger_min_confidence",)),
                    (trigger, ("min_confidence", "confidence")),
                    default=defaults.trigger_min_confidence,
                    name="trigger_min_confidence",
                ),
                "trigger_min_confidence",
                minimum=0.0,
                maximum=1.0,
            ),
            recoil_enabled=_strict_bool(
                _coalesced(
                    (raw, ("recoil_enabled",)),
                    (recoil, ("enabled",)),
                    default=defaults.recoil_enabled,
                    name="recoil_enabled",
                ),
                "recoil_enabled",
            ),
            recoil_scale_x=_bounded_float(
                _coalesced(
                    (raw, ("recoil_scale_x", "recoil_yaw_scale")),
                    (recoil, ("scale_x", "yaw_scale")),
                    default=defaults.recoil_scale_x,
                    name="recoil_scale_x",
                ),
                "recoil_scale_x",
                minimum=0.0,
                maximum=10.0,
            ),
            recoil_scale_y=_bounded_float(
                _coalesced(
                    (raw, ("recoil_scale_y", "recoil_pitch_scale")),
                    (recoil, ("scale_y", "pitch_scale")),
                    default=defaults.recoil_scale_y,
                    name="recoil_scale_y",
                ),
                "recoil_scale_y",
                minimum=0.0,
                maximum=10.0,
            ),
            require_visible=_strict_bool(raw.get("require_visible", defaults.require_visible), "require_visible"),
            require_alive=_strict_bool(raw.get("require_alive", defaults.require_alive), "require_alive"),
            require_hostile=_strict_bool(raw.get("require_hostile", defaults.require_hostile), "require_hostile"),
            initial_x=_bounded_float(
                _coalesced(
                    (raw, ("initial_x",)),
                    (initial_values, ("initial_x",)),
                    default=defaults.initial_x,
                    name="initial_x",
                ),
                "initial_x",
                minimum=-_MAX_COORDINATE,
                maximum=_MAX_COORDINATE,
            ),
            initial_y=_bounded_float(
                _coalesced(
                    (raw, ("initial_y",)),
                    (initial_values, ("initial_y",)),
                    default=defaults.initial_y,
                    name="initial_y",
                ),
                "initial_y",
                minimum=-_MAX_COORDINATE,
                maximum=_MAX_COORDINATE,
            ),
        )
        if config.fov_weight + config.distance_weight + config.confidence_weight <= 0.0:
            raise ValueError("at least one scoring weight must be greater than zero")
        return config

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_fov": self.max_fov,
            "max_distance": self.max_distance,
            "min_confidence": self.min_confidence,
            "weights": {
                "fov": self.fov_weight,
                "distance": self.distance_weight,
                "confidence": self.confidence_weight,
            },
            "smoothing_factor": self.smoothing_factor,
            "trajectory_steps": self.trajectory_steps,
            "max_step": self.max_step,
            "trigger": {
                "enabled": self.trigger_enabled,
                "radius": self.trigger_radius,
                "min_confidence": self.trigger_min_confidence,
            },
            "recoil_compensation": {
                "enabled": self.recoil_enabled,
                "scale_x": self.recoil_scale_x,
                "scale_y": self.recoil_scale_y,
            },
            "require_visible": self.require_visible,
            "require_alive": self.require_alive,
            "require_hostile": self.require_hostile,
            "initial_control": {"x": self.initial_x, "y": self.initial_y},
        }


def score_candidate(
    candidate: Mapping[str, Any],
    config: Optional[Mapping[str, Any] | SimulationConfig] = None,
) -> dict[str, Any]:
    """Normalize and score one observation without accessing external state."""

    cfg = _validated_config(config)
    normalized = _normalize_candidate(candidate, aim_origin=(0.0, 0.0), index=0)
    return _score_normalized_candidate(normalized, cfg)


def select_target(
    candidates: Sequence[Mapping[str, Any]],
    config: Optional[Mapping[str, Any] | SimulationConfig] = None,
) -> Optional[dict[str, Any]]:
    """Select the highest-ranked eligible candidate with a stable identity tie-break."""

    cfg = _validated_config(config)
    normalized = _normalize_candidate_sequence(candidates, aim_origin=(0.0, 0.0), frame_id="0")
    ranked = _rank_candidates(normalized, cfg)
    selected = next((item for item in ranked if item["eligible"]), None)
    return _json_clone(selected) if selected is not None else None


def simulate_target_control(
    frames: Sequence[Mapping[str, Any]],
    config: Optional[Mapping[str, Any] | SimulationConfig] = None,
) -> dict[str, Any]:
    """Run the deterministic numerical simulation over explicit offline frames."""

    cfg = _validated_config(config)
    normalized_frames = _normalize_frames(frames)
    return _simulate_normalized(normalized_frames, cfg)


class TargetControlProvider:
    """Capability provider for deterministic offline target-control simulation."""

    capability_name = "target_control_simulation"
    provider_name = "offline_target_control_simulator"
    priority = 10

    def supports(self, request: CapabilityRequest, context: Optional[dict[str, Any]] = None) -> bool:
        del context
        return request.capability == self.capability_name and _normalize_action(request.action) in _SUPPORTED_ACTIONS

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        del context
        action = _normalize_action(request.action)
        if action not in _SUPPORTED_ACTIONS:
            raise ValueError(f"unsupported target_control_simulation action: {action or request.action!r}")
        if request.capability != self.capability_name:
            raise ValueError(f"request capability must be {self.capability_name}")

        session_id = _session_id(request.session_id)
        target_identity = _target_payload(request.target)
        parameters = _normalize_request_parameters(request.params)
        precondition_payload = _precondition_payload(
            action=action,
            target_identity=target_identity,
            parameters=parameters,
        )
        precondition_hash = _sha256_json(precondition_payload)
        before_snapshot = _before_snapshot(parameters, target_identity, precondition_payload, precondition_hash)
        rollback_plan = _planned_rollback(session_id, parameters["config"])
        request_provenance = _json_clone(dict(request.provenance or {}))
        boundary = _offline_boundary()
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=action,
            parameters=parameters,
            steps=[
                {"order": 1, "action": "validate_offline_observations", "status": "planned"},
                {"order": 2, "action": "score_and_select_targets", "status": "planned"},
                {"order": 3, "action": "simulate_smoothed_control", "status": "planned"},
                {"order": 4, "action": "simulate_trigger_and_recoil", "status": "planned"},
                {"order": 5, "action": "persist_audit_artifacts", "status": "planned"},
            ],
            precondition_hash=precondition_hash,
            before_snapshot=before_snapshot,
            rollback_plan=rollback_plan,
            provenance={
                **request_provenance,
                "audit_schema_version": AUDIT_SCHEMA_VERSION,
                "algorithm": {"name": ALGORITHM_VERSION, "deterministic": True},
                "provider": self.provider_name,
                "boundary": boundary,
                "mocked": False,
                "dependency": boundary["dependency"],
                "simulation_only": True,
                "live_automated_target_control_completed": False,
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
            _normalize_action(plan.action) in _SUPPORTED_ACTIONS and plan.action == _normalize_action(plan.action),
            f"unsupported target_control_simulation action: {plan.action!r}",
            actual=plan.action,
        )
        try:
            _session_id(plan.session_id)
            session_ok = True
            session_error = ""
        except ValueError as exc:
            session_ok = False
            session_error = str(exc)
        check("session_id", session_ok, session_error or "invalid session_id", actual=plan.session_id)

        try:
            target_identity = _target_payload(plan.target)
            target_ok = True
            target_error = ""
        except (TypeError, ValueError) as exc:
            target_identity = {}
            target_ok = False
            target_error = str(exc)
        check("target_identity", target_ok, target_error or "invalid target identity", actual=target_identity)

        try:
            normalized_parameters = _normalize_planned_parameters(plan.parameters)
            parameters_ok = normalized_parameters == plan.parameters
            parameters_error = "" if parameters_ok else "plan parameters are not in canonical offline form"
        except (TypeError, ValueError) as exc:
            normalized_parameters = {}
            parameters_ok = False
            parameters_error = str(exc)
        check(
            "offline_parameters",
            parameters_ok,
            parameters_error or "invalid offline parameters",
            frame_count=len(normalized_parameters.get("frames") or []),
        )

        expected_hash = ""
        expected_before: dict[str, Any] = {}
        if target_ok and parameters_ok:
            precondition_payload = _precondition_payload(
                action=plan.action,
                target_identity=target_identity,
                parameters=normalized_parameters,
            )
            expected_hash = _sha256_json(precondition_payload)
            expected_before = _before_snapshot(
                normalized_parameters,
                target_identity,
                precondition_payload,
                expected_hash,
            )
        hash_ok = bool(expected_hash) and plan.precondition_hash == expected_hash
        check(
            "precondition_hash",
            hash_ok,
            "target-control precondition hash mismatch",
            expected=expected_hash,
            actual=plan.precondition_hash,
        )
        snapshot_ok = bool(expected_before) and plan.before_snapshot == expected_before
        check("before_snapshot", snapshot_ok, "before snapshot does not match the hashed offline inputs")

        boundary = _offline_boundary()
        boundary_ok = (
            parameters_ok
            and normalized_parameters.get("boundary") == boundary
            and isinstance(plan.provenance, Mapping)
            and plan.provenance.get("boundary") == boundary
            and plan.provenance.get("mocked") is False
            and plan.provenance.get("simulation_only") is True
            and plan.provenance.get("live_automated_target_control_completed") is False
        )
        check("offline_boundary", boundary_ok, "offline execution boundary was altered")

        rollback_expected = _planned_rollback(plan.session_id, normalized_parameters.get("config", {}))
        rollback_ok = parameters_ok and plan.rollback_plan == rollback_expected
        check("rollback_plan", rollback_ok, "rollback plan does not match the offline snapshot restore contract")

        return CapabilityValidation(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=str(plan.session_id or ""),
            ok=not errors,
            checks=checks,
            warnings=[
                "offline deterministic simulation only; no live automated target control was performed"
            ],
            errors=_dedupe(errors),
        )

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        validation = self.validate(plan, context=context)
        if validation.ok:
            config = SimulationConfig.from_mapping(plan.parameters["config"])
            simulation = _simulate_normalized(plan.parameters["frames"], config)
            status = "ok"
            errors: list[str] = []
            rollback_plan = {
                **_json_clone(plan.rollback_plan),
                "status": "ready",
                "simulation_completed": True,
            }
        else:
            simulation = {
                "schema_version": AUDIT_SCHEMA_VERSION,
                "algorithm": ALGORITHM_VERSION,
                "simulation_completed": False,
                "frames": [],
                "control_trajectory": [],
                "trigger_events": [],
                "errors": list(validation.errors),
            }
            status = "failed"
            errors = list(validation.errors)
            rollback_plan = {
                **_json_clone(plan.rollback_plan or {"supported": True}),
                "status": "not_required",
                "simulation_completed": False,
            }
        return self._execution_result(plan, validation, status, simulation, rollback_plan, errors)

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
                    "mode": "offline_snapshot_restore",
                    "external_state_changed": False,
                    "external_state_restored": False,
                    "simulation_state_restored": True,
                },
            )
        if result.status != "ok" or not result.after_snapshot.get("simulation_completed"):
            result.rollback_plan.update({"status": "not_required", "simulation_completed": False})
            _sync_report(result)
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=result.session_id,
                ok=True,
                restored=False,
                details={
                    "status": "not_required",
                    "reason": "no completed simulation state to restore",
                    "external_state_changed": False,
                },
            )

        initial_control = _json_clone(result.before_snapshot.get("initial_control") or {"x": 0.0, "y": 0.0})
        rollback_snapshot = {
            "mode": "offline_snapshot_restore",
            "control": initial_control,
            "trigger_events": [],
            "external_state_changed": False,
            "external_state_restored": False,
            "simulation_state_restored": True,
        }
        result.rollback_plan.update(
            {
                "status": "completed",
                "completed": True,
                "simulation_state_restored": True,
                "external_state_changed": False,
            }
        )
        result.after_snapshot["rollback_snapshot"] = rollback_snapshot
        result.dashboard_trace.append(
            {
                "kind": "target_control_simulation_rollback",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "session_id": result.session_id,
                "status": "completed",
                "external_state_changed": False,
            }
        )
        result.provenance["rollback"] = {
            "mode": "offline_snapshot_restore",
            "completed": True,
            "external_state_changed": False,
        }
        _sync_report(result)
        return CapabilityRollbackResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            ok=True,
            restored=True,
            details={"status": "completed", **rollback_snapshot},
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

        expected = _result_artifacts(result.session_id)
        expected_shape = [(item.path, item.kind) for item in expected]
        actual_shape = [(item.path, item.kind) for item in result.artifacts]
        if actual_shape != expected_shape:
            raise ValueError("target-control artifact descriptors were altered")

        by_kind = {item.kind: item for item in result.artifacts}
        audit_artifact = by_kind["target-control-audit"]
        simulation_artifact = by_kind["target-control-simulation"]
        manifest_artifact = by_kind["evidence-manifest"]

        payloads = {
            audit_artifact.kind: _audit_payload(result),
            simulation_artifact.kind: _simulation_payload(result),
        }
        data_entries: list[dict[str, Any]] = []
        encoded_by_kind: dict[str, bytes] = {}
        for artifact in (audit_artifact, simulation_artifact):
            encoded = _json_bytes(payloads[artifact.kind])
            encoded_by_kind[artifact.kind] = encoded
            data_entries.append(_materialized_entry(artifact, result, encoded))

        manifest_payload = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "status": result.status,
            "target_identity": _target_payload(result.target),
            "precondition_hash": result.provenance.get("precondition_hash"),
            "boundary": _offline_boundary(),
            "entry_count": len(data_entries),
            "entries": data_entries,
            "manifest_artifact": {
                "path": manifest_artifact.path,
                "kind": manifest_artifact.kind,
                "role": "artifact_manifest",
            },
        }
        manifest_encoded = _json_bytes(manifest_payload)
        encoded_by_kind[manifest_artifact.kind] = manifest_encoded
        manifest_entry = _materialized_entry(manifest_artifact, result, manifest_encoded)
        all_entries = data_entries + [manifest_entry]

        for artifact in result.artifacts:
            encoded = encoded_by_kind[artifact.kind]
            destination = _artifact_destination(root, artifact.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(encoded)
            artifact.metadata.update(
                {
                    "materialized": True,
                    "sha256": hashlib.sha256(encoded).hexdigest(),
                    "size": len(encoded),
                    "collection_root": str(root),
                }
            )

        result.evidence_manifest_entries = all_entries
        _sync_report(result)
        return CapabilityArtifactBundle(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            artifacts=list(result.artifacts),
            manifest_entries=all_entries,
        )

    def _execution_result(
        self,
        plan: CapabilityPlan,
        validation: CapabilityValidation,
        status: str,
        simulation: Mapping[str, Any],
        rollback_plan: Mapping[str, Any],
        errors: Sequence[str],
    ) -> CapabilityExecutionResult:
        artifacts = _result_artifacts(plan.session_id)
        selected_identity = _json_clone(simulation.get("final_selected_target_identity") or {})
        after_snapshot = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "mode": "offline_deterministic_simulation",
            "simulation_completed": bool(simulation.get("simulation_completed")),
            "selected_target_identity": selected_identity,
            "selected_target_identities": _json_clone(simulation.get("selected_target_identities") or []),
            "frame_count": simulation.get("frame_count", 0),
            "candidate_count": simulation.get("candidate_count", 0),
            "trigger_count": simulation.get("trigger_count", 0),
            "final_control": _json_clone(simulation.get("final_control") or {}),
            "simulation_hash": simulation.get("simulation_hash"),
            "simulation": _json_clone(simulation),
            "errors": list(errors),
            "external_state_changed": False,
        }
        provenance = {
            **_json_clone(plan.provenance),
            "precondition_hash": plan.precondition_hash,
            "plan": plan.to_dict(),
            "validation": validation.to_dict(),
            "execution_boundary": _offline_boundary(),
            "mocked": False,
            "dependency": {"required": False, "status": "not_required"},
            "simulation_completed": bool(simulation.get("simulation_completed")),
            "live_automated_target_control_completed": False,
        }
        result = CapabilityExecutionResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=_json_clone(plan.before_snapshot),
            after_snapshot=after_snapshot,
            rollback_plan=_json_clone(rollback_plan),
            artifacts=artifacts,
            evidence_manifest_entries=[],
            report_section={},
            dashboard_trace=[
                {
                    "kind": "target_control_simulation_execution",
                    "capability": self.capability_name,
                    "provider": self.provider_name,
                    "session_id": plan.session_id,
                    "status": status,
                    "action": plan.action,
                    "mode": "offline_deterministic_simulation",
                    "frame_count": simulation.get("frame_count", 0),
                    "candidate_count": simulation.get("candidate_count", 0),
                    "trigger_count": simulation.get("trigger_count", 0),
                    "selected_target_identity": selected_identity,
                    "live_automated_target_control_completed": False,
                }
            ],
            provenance=provenance,
        )
        result.evidence_manifest_entries = _planned_manifest_entries(result)
        result.report_section = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "status": result.status,
            "action": result.action,
            "mode": "offline_deterministic_simulation",
            "target_identity": _target_payload(result.target),
            "selected_target_identity": selected_identity,
            "precondition_hash": plan.precondition_hash,
            "simulation_completed": bool(simulation.get("simulation_completed")),
            "live_automated_target_control_completed": False,
            "mocked": False,
            "dependency": {"required": False, "status": "not_required"},
            "frame_count": simulation.get("frame_count", 0),
            "candidate_count": simulation.get("candidate_count", 0),
            "trigger_count": simulation.get("trigger_count", 0),
            "before_snapshot": result.before_snapshot,
            "after_snapshot": result.after_snapshot,
            "rollback_plan": result.rollback_plan,
            "provenance": result.provenance,
            "validation": validation.to_dict(),
            "errors": list(errors),
            "artifacts": [item.to_dict() for item in artifacts],
            "evidence_manifest_entries": list(result.evidence_manifest_entries),
        }
        return result

    def _require_result(self, result: CapabilityExecutionResult) -> None:
        if result.capability != self.capability_name or result.provider != self.provider_name:
            raise ValueError("capability result does not belong to the target-control simulator")
        if result.action not in _SUPPORTED_ACTIONS:
            raise ValueError("target-control result action is unsupported")
        _session_id(result.session_id)
        _target_payload(result.target)
        boundary = result.provenance.get("execution_boundary") if isinstance(result.provenance, Mapping) else None
        if boundary != _offline_boundary():
            raise ValueError("target-control result offline boundary is missing or altered")
        if not _valid_sha256(result.provenance.get("precondition_hash")):
            raise ValueError("target-control result precondition hash is missing")
        if result.provenance.get("mocked") is not False:
            raise ValueError("target-control result mocked boundary is not truthful")
        if result.provenance.get("live_automated_target_control_completed") is not False:
            raise ValueError("live target control cannot be completed by the offline simulator")


TargetControlSimulationProvider = TargetControlProvider


def _validated_config(
    value: Optional[Mapping[str, Any] | SimulationConfig],
) -> SimulationConfig:
    raw = value.to_dict() if isinstance(value, SimulationConfig) else value
    return SimulationConfig.from_mapping(raw)


def _normalize_action(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _session_id(value: Any) -> str:
    session_id = str(value or "target-control-simulation-session").strip()
    if not session_id or len(session_id) > _MAX_SESSION_LENGTH or not _SESSION_RE.fullmatch(session_id):
        raise ValueError("session_id must be 1-128 characters using letters, digits, '.', '_', or '-'")
    return session_id


def _target_payload(target: TargetIdentity) -> dict[str, Any]:
    if not isinstance(target, TargetIdentity):
        raise TypeError("target must be a TargetIdentity")
    payload = _json_clone(target.to_dict())
    kind = str(payload.get("kind") or "").strip()
    if not kind or len(kind) > _MAX_IDENTITY_LENGTH:
        raise ValueError("target.kind must contain 1-256 characters")
    if not any(payload.get(key) not in (None, "") for key in ("path", "pid", "sha256", "display_name")):
        raise ValueError("offline target identity requires path, pid, sha256, or display_name")
    if payload.get("pid") is not None and (
        isinstance(payload["pid"], bool) or not isinstance(payload["pid"], int) or payload["pid"] <= 0
    ):
        raise ValueError("target.pid must be a positive integer")
    if payload.get("sha256") is not None and not _valid_sha256(payload["sha256"]):
        raise ValueError("target.sha256 must be a 64-character hexadecimal digest")
    for key, maximum in (("path", 4096), ("display_name", _MAX_IDENTITY_LENGTH)):
        if payload.get(key) is not None:
            text = str(payload[key])
            if not text or len(text) > maximum or "\x00" in text:
                raise ValueError(f"target.{key} is invalid")
            payload[key] = text
    payload["kind"] = kind
    return payload


def _normalize_request_parameters(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise TypeError("params must be a mapping")
    params = _json_clone(dict(raw))
    _enforce_parameter_size(params)
    unknown = sorted(set(params) - {"frames", "observations", "config"} - _CONFIG_KEYS)
    if unknown:
        raise ValueError("unknown target-control parameters: " + ", ".join(unknown))
    has_frames = "frames" in params
    has_observations = "observations" in params
    if has_frames == has_observations:
        raise ValueError("provide exactly one of frames or observations")

    config_raw = params.get("config", {})
    if not isinstance(config_raw, Mapping):
        raise TypeError("config must be a mapping")
    merged_config = dict(config_raw)
    for key in sorted(_CONFIG_KEYS):
        if key not in params:
            continue
        if key in merged_config and _canonical_json(merged_config[key]) != _canonical_json(params[key]):
            raise ValueError(f"conflicting config value for {key}")
        merged_config[key] = params[key]
    config = SimulationConfig.from_mapping(merged_config)

    if has_frames:
        source_kind = "frames"
        frame_values = params["frames"]
    else:
        source_kind = "observations"
        frame_values = _frames_from_observations(params["observations"])
    frames = _normalize_frames(frame_values)
    return {
        "source_kind": source_kind,
        "frames": frames,
        "config": config.to_dict(),
        "boundary": _offline_boundary(),
    }


def _normalize_planned_parameters(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise TypeError("plan parameters must be a mapping")
    if set(raw) != {"source_kind", "frames", "config", "boundary"}:
        raise ValueError("plan parameters must contain only source_kind, frames, config, and boundary")
    source_kind = raw.get("source_kind")
    if source_kind not in {"frames", "observations"}:
        raise ValueError("source_kind must be frames or observations")
    frames = _normalize_frames(raw.get("frames"))
    config = SimulationConfig.from_mapping(raw.get("config")).to_dict()
    boundary = _json_clone(raw.get("boundary"))
    if boundary != _offline_boundary():
        raise ValueError("plan boundary must remain offline-only")
    normalized = {
        "source_kind": source_kind,
        "frames": frames,
        "config": config,
        "boundary": boundary,
    }
    _enforce_parameter_size(normalized)
    return normalized


def _frames_from_observations(value: Any) -> list[dict[str, Any]]:
    observations = _sequence(value, "observations")
    if not observations:
        raise ValueError("observations must contain at least one item")
    mappings = [_mapping(item, f"observations[{index}]") for index, item in enumerate(observations)]
    collection_keys = {"candidates", "observations", "targets", "detections"}
    as_frames = [bool(collection_keys.intersection(item)) for item in mappings]
    if any(as_frames):
        if not all(as_frames):
            raise ValueError("observations cannot mix frame records and flat candidate records")
        return mappings

    frame_markers = ("frame_id", "frame", "frame_index")
    if not any(any(key in item for key in frame_markers) for item in mappings):
        return [{"frame_id": "0", "observations": mappings}]

    grouped: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for index, observation in enumerate(mappings):
        frame_id = _identity_text(
            _first_present(observation, frame_markers, default=index),
            f"observations[{index}].frame_id",
        )
        if frame_id not in grouped:
            grouped[frame_id] = {
                "frame_id": frame_id,
                "timestamp_ms": _first_present(
                    observation,
                    ("timestamp_ms", "time_ms", "timestamp"),
                    default=len(order),
                ),
                "aim_origin": observation.get("aim_origin", observation.get("crosshair", {"x": 0.0, "y": 0.0})),
                "recoil": observation.get("recoil", {"x": 0.0, "y": 0.0}),
                "observations": [],
            }
            order.append(frame_id)
        grouped[frame_id]["observations"].append(observation)
    return [grouped[key] for key in order]


def _normalize_frames(value: Any) -> list[dict[str, Any]]:
    raw_frames = _sequence(value, "frames")
    if not raw_frames:
        raise ValueError("frames must contain at least one frame")
    if len(raw_frames) > MAX_FRAMES:
        raise ValueError(f"frames exceeds the maximum of {MAX_FRAMES}")

    frames: list[dict[str, Any]] = []
    seen_frame_ids: set[str] = set()
    total_candidates = 0
    previous_timestamp = -1.0
    for index, raw in enumerate(raw_frames):
        frame = _mapping(raw, f"frames[{index}]")
        frame_id = _identity_text(
            _first_present(frame, ("frame_id", "id", "frame_index"), default=index),
            f"frames[{index}].frame_id",
        )
        if frame_id in seen_frame_ids:
            raise ValueError(f"duplicate frame identity: {frame_id}")
        seen_frame_ids.add(frame_id)
        timestamp = _bounded_float(
            _first_present(frame, ("timestamp_ms", "time_ms", "timestamp"), default=index),
            f"frames[{index}].timestamp_ms",
            minimum=0.0,
            maximum=float(_MAX_TIMESTAMP_MS),
        )
        if timestamp < previous_timestamp:
            raise ValueError("frame timestamps must be nondecreasing")
        previous_timestamp = timestamp
        origin = _pair(
            _first_present(frame, ("aim_origin", "crosshair", "origin"), default={"x": 0.0, "y": 0.0}),
            f"frames[{index}].aim_origin",
            limit=1_000_000.0,
        )
        recoil = _normalize_recoil(frame, index)
        candidate_values = _first_present(
            frame,
            ("candidates", "observations", "targets", "detections"),
            default=[],
        )
        candidates = _normalize_candidate_sequence(candidate_values, aim_origin=origin, frame_id=frame_id)
        total_candidates += len(candidates)
        if total_candidates > MAX_TOTAL_CANDIDATES:
            raise ValueError(f"total candidate count exceeds the maximum of {MAX_TOTAL_CANDIDATES}")
        frames.append(
            {
                "frame_id": frame_id,
                "timestamp_ms": timestamp,
                "aim_origin": {"x": origin[0], "y": origin[1]},
                "recoil": recoil,
                "candidates": candidates,
            }
        )
    return frames


def _normalize_candidate_sequence(value: Any, *, aim_origin: tuple[float, float], frame_id: str) -> list[dict[str, Any]]:
    candidates = _sequence(value, f"frame {frame_id} candidates")
    if len(candidates) > MAX_CANDIDATES_PER_FRAME:
        raise ValueError(f"frame {frame_id} exceeds {MAX_CANDIDATES_PER_FRAME} candidates")
    normalized = [
        _normalize_candidate(candidate, aim_origin=aim_origin, index=index)
        for index, candidate in enumerate(candidates)
    ]
    target_ids = [item["target_id"] for item in normalized]
    if len(set(target_ids)) != len(target_ids):
        raise ValueError(f"frame {frame_id} contains duplicate target identities")
    return sorted(normalized, key=lambda item: item["target_id"])


def _normalize_candidate(value: Any, *, aim_origin: tuple[float, float], index: int) -> dict[str, Any]:
    candidate = _mapping(value, f"candidate[{index}]")
    identity = _candidate_identity(candidate, index)
    offset_x, offset_y = _candidate_offset(candidate, aim_origin, index)
    fov = _round_float(math.hypot(offset_x, offset_y))
    if "fov" in candidate:
        declared_fov = _bounded_float(candidate["fov"], f"candidate[{index}].fov", 0.0, _MAX_COORDINATE * math.sqrt(2.0))
        if not _candidate_has_coordinates(candidate):
            fov = declared_fov
            offset_x, offset_y = declared_fov, 0.0
    distance = _candidate_distance(candidate, index)
    confidence = _bounded_float(
        _first_present(candidate, ("confidence", "score", "probability"), required=True),
        f"candidate[{index}].confidence",
        minimum=0.0,
        maximum=1.0,
    )
    visible = _candidate_flag(candidate, ("visible", "is_visible"), True, f"candidate[{index}].visible")
    alive = _candidate_flag(candidate, ("alive", "is_alive"), True, f"candidate[{index}].alive")
    hostile = _candidate_hostile(candidate, index)
    enabled = _candidate_flag(
        candidate,
        ("eligible", "selectable", "enabled"),
        True,
        f"candidate[{index}].eligible",
    )
    return {
        "target_id": identity["id"],
        "target_identity": identity,
        "offset": {"x": offset_x, "y": offset_y},
        "fov": fov,
        "distance": distance,
        "confidence": confidence,
        "visible": visible,
        "alive": alive,
        "hostile": hostile,
        "enabled": enabled,
    }


def _candidate_identity(candidate: Mapping[str, Any], index: int) -> dict[str, Any]:
    raw_identity = _first_present(candidate, ("target_identity", "identity"), default=None)
    if isinstance(raw_identity, Mapping):
        identity = _json_clone(dict(raw_identity))
        raw_id = _first_present(identity, ("id", "target_id", "track_id", "name", "display_name"), default=None)
    elif raw_identity not in (None, ""):
        raw_id = raw_identity
        identity = {}
    else:
        raw_id = _first_present(
            candidate,
            ("target_id", "id", "track_id", "name", "display_name"),
            required=True,
        )
        identity = {}
    target_id = _identity_text(raw_id, f"candidate[{index}].target_id")
    identity["id"] = target_id
    return {str(key): identity[key] for key in sorted(identity)}


def _candidate_has_coordinates(candidate: Mapping[str, Any]) -> bool:
    direct_pairs = (
        ("offset_x", "offset_y"),
        ("aim_x", "aim_y"),
        ("yaw", "pitch"),
        ("x", "y"),
        ("screen_x", "screen_y"),
    )
    return any(left in candidate or right in candidate for left, right in direct_pairs) or any(
        key in candidate for key in ("offset", "aim_offset", "screen_position", "center", "bbox")
    )


def _candidate_offset(candidate: Mapping[str, Any], origin: tuple[float, float], index: int) -> tuple[float, float]:
    for key in ("offset", "aim_offset"):
        if key in candidate:
            return _pair(candidate[key], f"candidate[{index}].{key}", limit=_MAX_COORDINATE)
    for left, right in (("offset_x", "offset_y"), ("aim_x", "aim_y"), ("yaw", "pitch"), ("x", "y")):
        if left in candidate or right in candidate:
            if left not in candidate or right not in candidate:
                raise ValueError(f"candidate[{index}] must provide both {left} and {right}")
            return (
                _bounded_float(candidate[left], f"candidate[{index}].{left}", -_MAX_COORDINATE, _MAX_COORDINATE),
                _bounded_float(candidate[right], f"candidate[{index}].{right}", -_MAX_COORDINATE, _MAX_COORDINATE),
            )
    for key in ("screen_position", "center"):
        if key in candidate:
            x, y = _pair(candidate[key], f"candidate[{index}].{key}", limit=1_000_000.0)
            return _screen_offset(x, y, origin, index)
    if "screen_x" in candidate or "screen_y" in candidate:
        if "screen_x" not in candidate or "screen_y" not in candidate:
            raise ValueError(f"candidate[{index}] must provide both screen_x and screen_y")
        x = _bounded_float(candidate["screen_x"], f"candidate[{index}].screen_x", -1_000_000.0, 1_000_000.0)
        y = _bounded_float(candidate["screen_y"], f"candidate[{index}].screen_y", -1_000_000.0, 1_000_000.0)
        return _screen_offset(x, y, origin, index)
    if "bbox" in candidate:
        bbox = _sequence(candidate["bbox"], f"candidate[{index}].bbox")
        if len(bbox) != 4:
            raise ValueError(f"candidate[{index}].bbox must contain x, y, width, height")
        x, y, width, height = [
            _bounded_float(item, f"candidate[{index}].bbox[{item_index}]", -1_000_000.0, 1_000_000.0)
            for item_index, item in enumerate(bbox)
        ]
        if width < 0.0 or height < 0.0:
            raise ValueError(f"candidate[{index}].bbox width and height must be nonnegative")
        return _screen_offset(x + width / 2.0, y + height / 2.0, origin, index)
    if "fov" in candidate:
        fov = _bounded_float(candidate["fov"], f"candidate[{index}].fov", 0.0, _MAX_FOV)
        return fov, 0.0
    raise ValueError(f"candidate[{index}] requires a finite two-dimensional offset or fov")


def _screen_offset(x: float, y: float, origin: tuple[float, float], index: int) -> tuple[float, float]:
    offset_x = _round_float(x - origin[0])
    offset_y = _round_float(y - origin[1])
    if abs(offset_x) > _MAX_COORDINATE or abs(offset_y) > _MAX_COORDINATE:
        raise ValueError(f"candidate[{index}] screen offset exceeds {_MAX_COORDINATE}")
    return offset_x, offset_y


def _candidate_distance(candidate: Mapping[str, Any], index: int) -> float:
    direct = _first_present(candidate, ("distance", "range", "depth"), default=None)
    if direct is not None:
        return _bounded_float(direct, f"candidate[{index}].distance", 0.0, _MAX_DISTANCE)
    position = candidate.get("position")
    if isinstance(position, Mapping) and all(key in position for key in ("x", "y", "z")):
        coordinates = [
            _bounded_float(position[key], f"candidate[{index}].position.{key}", -_MAX_DISTANCE, _MAX_DISTANCE)
            for key in ("x", "y", "z")
        ]
        return _round_float(math.sqrt(sum(item * item for item in coordinates)))
    raise ValueError(f"candidate[{index}] requires a finite distance")


def _candidate_flag(
    candidate: Mapping[str, Any],
    names: Sequence[str],
    default: bool,
    label: str,
) -> bool:
    values = [(name, candidate[name]) for name in names if name in candidate]
    if not values:
        return default
    normalized = [_strict_bool(value, f"{label} ({name})") for name, value in values]
    if len(set(normalized)) != 1:
        raise ValueError(f"conflicting values for {label}")
    return normalized[0]


def _candidate_hostile(candidate: Mapping[str, Any], index: int) -> bool:
    direct_names = ("hostile", "is_hostile", "enemy", "is_enemy")
    if any(name in candidate for name in direct_names):
        return _candidate_flag(candidate, direct_names, True, f"candidate[{index}].hostile")
    team = candidate.get("team")
    if team is None:
        return True
    normalized = str(team).strip().lower()
    if normalized in {"enemy", "hostile", "opponent"}:
        return True
    if normalized in {"ally", "friendly", "self", "neutral"}:
        return False
    raise ValueError(f"candidate[{index}].team must identify enemy/hostile or ally/friendly")


def _normalize_recoil(frame: Mapping[str, Any], index: int) -> dict[str, float]:
    if "recoil" in frame:
        x, y = _pair(frame["recoil"], f"frames[{index}].recoil", limit=_MAX_COORDINATE)
        return {"x": x, "y": y}
    x = _first_present(frame, ("recoil_x", "recoil_yaw"), default=0.0)
    y = _first_present(frame, ("recoil_y", "recoil_pitch"), default=0.0)
    return {
        "x": _bounded_float(x, f"frames[{index}].recoil_x", -_MAX_COORDINATE, _MAX_COORDINATE),
        "y": _bounded_float(y, f"frames[{index}].recoil_y", -_MAX_COORDINATE, _MAX_COORDINATE),
    }


def _score_normalized_candidate(candidate: Mapping[str, Any], config: SimulationConfig) -> dict[str, Any]:
    fov_component = _round_float(max(0.0, 1.0 - float(candidate["fov"]) / config.max_fov))
    distance_component = _round_float(max(0.0, 1.0 - float(candidate["distance"]) / config.max_distance))
    confidence_component = float(candidate["confidence"])
    weight_total = config.fov_weight + config.distance_weight + config.confidence_weight
    score = _round_float(
        (
            fov_component * config.fov_weight
            + distance_component * config.distance_weight
            + confidence_component * config.confidence_weight
        )
        / weight_total
    )
    reasons: list[str] = []
    if not candidate["enabled"]:
        reasons.append("candidate_disabled")
    if config.require_visible and not candidate["visible"]:
        reasons.append("not_visible")
    if config.require_alive and not candidate["alive"]:
        reasons.append("not_alive")
    if config.require_hostile and not candidate["hostile"]:
        reasons.append("not_hostile")
    if float(candidate["confidence"]) < config.min_confidence:
        reasons.append("confidence_below_minimum")
    if float(candidate["fov"]) > config.max_fov:
        reasons.append("outside_fov")
    if float(candidate["distance"]) > config.max_distance:
        reasons.append("outside_distance")
    return {
        **_json_clone(candidate),
        "score_components": {
            "fov": fov_component,
            "distance": distance_component,
            "confidence": confidence_component,
        },
        "score": score,
        "eligible": not reasons,
        "rejection_reasons": reasons,
    }


def _rank_candidates(candidates: Sequence[Mapping[str, Any]], config: SimulationConfig) -> list[dict[str, Any]]:
    scored = [_score_normalized_candidate(candidate, config) for candidate in candidates]

    def rank(item: Mapping[str, Any]) -> tuple[Any, ...]:
        if not item["eligible"]:
            return (1, str(item["target_id"]))
        return (
            0,
            -float(item["score"]),
            float(item["fov"]),
            float(item["distance"]),
            -float(item["confidence"]),
            str(item["target_id"]),
        )

    return sorted(scored, key=rank)


def _simulate_normalized(frames: Sequence[Mapping[str, Any]], config: SimulationConfig) -> dict[str, Any]:
    current_x = config.initial_x
    current_y = config.initial_y
    frame_results: list[dict[str, Any]] = []
    control_trajectory: list[dict[str, Any]] = []
    trigger_events: list[dict[str, Any]] = []
    selected_identities: list[dict[str, Any]] = []
    candidate_count = 0

    for frame_index, frame in enumerate(frames):
        ranked = _rank_candidates(frame["candidates"], config)
        candidate_count += len(ranked)
        selected = next((item for item in ranked if item["eligible"]), None)
        start = {"x": _round_float(current_x), "y": _round_float(current_y)}
        observed_recoil = _json_clone(frame["recoil"])
        compensation = {"x": 0.0, "y": 0.0}
        trajectory: list[dict[str, Any]] = []

        if selected is not None:
            if config.recoil_enabled:
                compensation = {
                    "x": _round_float(-float(observed_recoil["x"]) * config.recoil_scale_x),
                    "y": _round_float(-float(observed_recoil["y"]) * config.recoil_scale_y),
                }
            desired_x = _round_float(float(selected["offset"]["x"]) + compensation["x"])
            desired_y = _round_float(float(selected["offset"]["y"]) + compensation["y"])
            for step_index in range(config.trajectory_steps):
                delta_x = desired_x - current_x
                delta_y = desired_y - current_y
                command_x = delta_x * config.smoothing_factor
                command_y = delta_y * config.smoothing_factor
                command_norm = math.hypot(command_x, command_y)
                if command_norm > config.max_step:
                    scale = config.max_step / command_norm
                    command_x *= scale
                    command_y *= scale
                current_x = _round_float(current_x + command_x)
                current_y = _round_float(current_y + command_y)
                point = {
                    "frame_id": frame["frame_id"],
                    "frame_index": frame_index,
                    "step": step_index + 1,
                    "target_id": selected["target_id"],
                    "command": {"x": _round_float(command_x), "y": _round_float(command_y)},
                    "control": {"x": current_x, "y": current_y},
                    "residual": _round_float(math.hypot(desired_x - current_x, desired_y - current_y)),
                }
                trajectory.append(point)
                control_trajectory.append(point)
        else:
            desired_x = current_x
            desired_y = current_y

        residual = _round_float(math.hypot(desired_x - current_x, desired_y - current_y))
        trigger = _trigger_result(selected, config, residual)
        if trigger["would_trigger"] and selected is not None:
            trigger_event = {
                "frame_id": frame["frame_id"],
                "frame_index": frame_index,
                "target_id": selected["target_id"],
                "target_identity": _json_clone(selected["target_identity"]),
                "residual": residual,
                "simulated_only": True,
                "input_emitted": False,
            }
            trigger_events.append(trigger_event)
        if selected is not None:
            selected_identities.append(_json_clone(selected["target_identity"]))

        frame_results.append(
            {
                "frame_id": frame["frame_id"],
                "frame_index": frame_index,
                "timestamp_ms": frame["timestamp_ms"],
                "candidate_count": len(ranked),
                "eligible_count": sum(1 for item in ranked if item["eligible"]),
                "candidate_scores": ranked,
                "selected_target": _json_clone(selected) if selected is not None else None,
                "recoil": {
                    "observed": observed_recoil,
                    "compensation": compensation,
                    "enabled": config.recoil_enabled,
                },
                "control": {
                    "start": start,
                    "desired": {"x": _round_float(desired_x), "y": _round_float(desired_y)},
                    "trajectory": trajectory,
                    "end": {"x": _round_float(current_x), "y": _round_float(current_y)},
                    "residual": residual,
                },
                "trigger": trigger,
            }
        )

    final_identity = selected_identities[-1] if selected_identities else {}
    payload = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "algorithm": ALGORITHM_VERSION,
        "deterministic": True,
        "mode": "offline_deterministic_simulation",
        "simulation_completed": True,
        "frame_count": len(frames),
        "candidate_count": candidate_count,
        "selected_frame_count": len(selected_identities),
        "selected_target_identities": selected_identities,
        "final_selected_target_identity": final_identity,
        "frames": frame_results,
        "control_trajectory": control_trajectory,
        "final_control": {"x": _round_float(current_x), "y": _round_float(current_y)},
        "trigger_count": len(trigger_events),
        "trigger_events": trigger_events,
        "boundary": _offline_boundary(),
    }
    payload["simulation_hash"] = _sha256_json(payload)
    return payload


def _trigger_result(
    selected: Optional[Mapping[str, Any]],
    config: SimulationConfig,
    residual: float,
) -> dict[str, Any]:
    if not config.trigger_enabled:
        reason = "disabled"
        would_trigger = False
    elif selected is None:
        reason = "no_eligible_target"
        would_trigger = False
    elif float(selected["confidence"]) < config.trigger_min_confidence:
        reason = "confidence_below_trigger_threshold"
        would_trigger = False
    elif residual > config.trigger_radius:
        reason = "outside_trigger_radius"
        would_trigger = False
    else:
        reason = "within_trigger_thresholds"
        would_trigger = True
    return {
        "enabled": config.trigger_enabled,
        "would_trigger": would_trigger,
        "reason": reason,
        "residual": residual,
        "radius": config.trigger_radius,
        "minimum_confidence": config.trigger_min_confidence,
        "simulated_only": True,
        "input_emitted": False,
    }


def _precondition_payload(
    *,
    action: str,
    target_identity: Mapping[str, Any],
    parameters: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "capability": TargetControlProvider.capability_name,
        "algorithm": ALGORITHM_VERSION,
        "action": action,
        "target_identity": _json_clone(target_identity),
        "source_kind": parameters["source_kind"],
        "frames": _json_clone(parameters["frames"]),
        "config": _json_clone(parameters["config"]),
        "boundary": _offline_boundary(),
    }


def _before_snapshot(
    parameters: Mapping[str, Any],
    target_identity: Mapping[str, Any],
    precondition_payload: Mapping[str, Any],
    precondition_hash: str,
) -> dict[str, Any]:
    frames = parameters["frames"]
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "capture_phase": "plan",
        "mode": "offline_deterministic_simulation",
        "source_kind": parameters["source_kind"],
        "target_identity": _json_clone(target_identity),
        "frame_count": len(frames),
        "candidate_count": sum(len(frame["candidates"]) for frame in frames),
        "frames": _json_clone(frames),
        "config": _json_clone(parameters["config"]),
        "initial_control": _json_clone(parameters["config"]["initial_control"]),
        "precondition_payload": _json_clone(precondition_payload),
        "precondition_hash": precondition_hash,
        "external_state_observed": False,
        "external_state_changed": False,
        "boundary": _offline_boundary(),
    }


def _planned_rollback(session_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
    initial = config.get("initial_control") if isinstance(config, Mapping) else None
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "supported": True,
        "status": "planned",
        "mode": "offline_snapshot_restore",
        "session_id": session_id,
        "idempotent": True,
        "restore_to": _json_clone(initial or {"x": 0.0, "y": 0.0}),
        "external_side_effects": False,
    }


def _result_artifacts(session_id: str) -> list[CapabilityArtifact]:
    root = f"target_control/{_safe_segment(session_id)}"
    return [
        CapabilityArtifact(
            path=f"{root}/audit.json",
            kind="target-control-audit",
            description="Offline target-control lifecycle and boundary audit",
        ),
        CapabilityArtifact(
            path=f"{root}/simulation.json",
            kind="target-control-simulation",
            description="Deterministic target scoring and numerical control trajectory",
        ),
        CapabilityArtifact(
            path=f"{root}/manifest.json",
            kind="evidence-manifest",
            description="SHA-256 manifest for target-control simulation artifacts",
        ),
    ]


def _planned_manifest_entries(result: CapabilityExecutionResult) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for artifact in result.artifacts:
        entries.append(
            {
                "path": artifact.path,
                "kind": artifact.kind,
                "role": "artifact_manifest" if artifact.kind == "evidence-manifest" else artifact.kind,
                "description": artifact.description,
                "status": result.status,
                "session_id": result.session_id,
                "target_identity": _target_payload(result.target),
                "precondition_hash": result.provenance.get("precondition_hash"),
                "materialized": False,
            }
        )
    return entries


def _materialized_entry(
    artifact: CapabilityArtifact,
    result: CapabilityExecutionResult,
    encoded: bytes,
) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "role": "artifact_manifest" if artifact.kind == "evidence-manifest" else artifact.kind,
        "description": artifact.description,
        "status": result.status,
        "session_id": result.session_id,
        "target_identity": _target_payload(result.target),
        "precondition_hash": result.provenance.get("precondition_hash"),
        "materialized": True,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "size": len(encoded),
    }


def _audit_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "session_id": result.session_id,
        "status": result.status,
        "action": result.action,
        "mode": "offline_deterministic_simulation",
        "target_identity": _target_payload(result.target),
        "selected_target_identity": _json_clone(result.after_snapshot.get("selected_target_identity") or {}),
        "precondition_hash": result.provenance.get("precondition_hash"),
        "before_snapshot": _json_clone(result.before_snapshot),
        "after_snapshot": _json_clone(result.after_snapshot),
        "rollback_plan": _json_clone(result.rollback_plan),
        "provenance": _json_clone(result.provenance),
        "evidence_manifest_entries": _planned_manifest_entries(result),
        "report_section": _stable_report_section(result),
        "dashboard_trace": _json_clone(result.dashboard_trace),
        "events": _audit_events(result),
        "boundary": _offline_boundary(),
        "live_automated_target_control_completed": False,
    }


def _simulation_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "session_id": result.session_id,
        "status": result.status,
        "action": result.action,
        "target_identity": _target_payload(result.target),
        "precondition_hash": result.provenance.get("precondition_hash"),
        "simulation": _json_clone(result.after_snapshot.get("simulation") or {}),
        "boundary": _offline_boundary(),
    }


def _stable_report_section(result: CapabilityExecutionResult) -> dict[str, Any]:
    report = _json_clone(result.report_section)
    report.pop("artifacts", None)
    report.pop("evidence_manifest_entries", None)
    return report


def _audit_events(result: CapabilityExecutionResult) -> list[dict[str, Any]]:
    validation = result.provenance.get("validation") if isinstance(result.provenance, Mapping) else {}
    events = [
        {
            "kind": "plan",
            "ts": "1970-01-01T00:00:00Z",
            "message": "hashed explicit offline observations and simulation parameters",
            "clock": "deterministic_logical",
        },
        {
            "kind": "validate",
            "ts": "1970-01-01T00:00:01Z",
            "message": "validated finite bounded inputs and offline execution boundary",
            "clock": "deterministic_logical",
            "ok": bool(validation.get("ok")) if isinstance(validation, Mapping) else False,
        },
        {
            "kind": "execute",
            "ts": "1970-01-01T00:00:02Z",
            "message": "completed deterministic numerical simulation" if result.status == "ok" else "simulation rejected",
            "clock": "deterministic_logical",
            "status": result.status,
            "external_state_changed": False,
        },
    ]
    if result.rollback_plan.get("status") == "completed":
        events.append(
            {
                "kind": "rollback",
                "ts": "1970-01-01T00:00:03Z",
                "message": "restored the in-memory simulation snapshot",
                "clock": "deterministic_logical",
                "external_state_changed": False,
            }
        )
    return events


def _sync_report(result: CapabilityExecutionResult) -> None:
    result.report_section["after_snapshot"] = _json_clone(result.after_snapshot)
    result.report_section["rollback_plan"] = _json_clone(result.rollback_plan)
    result.report_section["provenance"] = _json_clone(result.provenance)
    result.report_section["artifacts"] = [item.to_dict() for item in result.artifacts]
    result.report_section["evidence_manifest_entries"] = _json_clone(result.evidence_manifest_entries)


def _artifact_destination(root: Path, relative_path: str) -> Path:
    posix = PurePosixPath(str(relative_path).replace("\\", "/"))
    windows = PureWindowsPath(str(relative_path))
    if posix.is_absolute() or windows.is_absolute() or windows.drive or ".." in posix.parts or ".." in windows.parts:
        raise ValueError("artifact path must stay within the collection directory")
    destination = root.joinpath(*posix.parts).resolve()
    destination.relative_to(root)
    return destination


def _nested_config(value: Any, name: str, allowed: set[str]) -> dict[str, Any]:
    if value is None:
        return {}
    nested = _mapping(value, name)
    unknown = sorted(set(nested) - allowed)
    if unknown:
        raise ValueError(f"unknown {name} fields: " + ", ".join(unknown))
    return nested


def _nested_toggle(value: Any, name: str, allowed: set[str]) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, bool):
        return {"enabled": value}
    return _nested_config(value, name, allowed)


def _coalesced(
    *sources: tuple[Mapping[str, Any], Sequence[str]],
    default: Any,
    name: str,
) -> Any:
    values: list[Any] = []
    for source, keys in sources:
        for key in keys:
            if key in source:
                values.append(source[key])
    if not values:
        return default
    canonical = {_canonical_json(item) for item in values}
    if len(canonical) != 1:
        raise ValueError(f"conflicting values for {name}")
    return values[0]


def _first_present(
    value: Mapping[str, Any],
    names: Sequence[str],
    *,
    default: Any = None,
    required: bool = False,
) -> Any:
    found = [(name, value[name]) for name in names if name in value]
    if not found:
        if required:
            raise ValueError("missing required field: " + " or ".join(names))
        return default
    canonical = {_canonical_json(item) for _, item in found}
    if len(canonical) != 1:
        raise ValueError("conflicting values for " + "/".join(names))
    return found[0][1]


def _pair(value: Any, name: str, *, limit: float) -> tuple[float, float]:
    if isinstance(value, Mapping):
        if "x" not in value or "y" not in value:
            raise ValueError(f"{name} must contain x and y")
        raw_x, raw_y = value["x"], value["y"]
    else:
        items = _sequence(value, name)
        if len(items) != 2:
            raise ValueError(f"{name} must contain exactly two values")
        raw_x, raw_y = items
    return (
        _bounded_float(raw_x, f"{name}.x", -limit, limit),
        _bounded_float(raw_y, f"{name}.y", -limit, limit),
    )


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping")
    return dict(value)


def _sequence(value: Any, name: str) -> list[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TypeError(f"{name} must be a sequence")
    return list(value)


def _identity_text(value: Any, name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise TypeError(f"{name} must be a string or integer")
    text = str(value).strip()
    if not text or len(text) > _MAX_IDENTITY_LENGTH or "\x00" in text:
        raise ValueError(f"{name} must contain 1-{_MAX_IDENTITY_LENGTH} characters without NUL")
    return text


def _strict_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a boolean")
    return value


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be from {minimum} to {maximum}")
    return value


def _bounded_float(value: Any, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a finite number")
    try:
        number = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be finite and representable") from exc
    if not math.isfinite(number):
        raise ValueError(f"{name} must be finite")
    if number < minimum or number > maximum:
        raise ValueError(f"{name} must be from {minimum} to {maximum}")
    return _round_float(number)


def _round_float(value: float) -> float:
    rounded = round(float(value), _FLOAT_DIGITS)
    return 0.0 if rounded == 0.0 else rounded


def _json_clone(value: Any) -> Any:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError(f"value must be finite JSON data: {exc}") from exc
    return json.loads(encoded)


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError(f"value must be finite JSON data: {exc}") from exc


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _enforce_parameter_size(value: Any) -> None:
    size = len(_canonical_json(value).encode("utf-8"))
    if size > MAX_PARAMETER_JSON_BYTES:
        raise ValueError(f"target-control parameters exceed {MAX_PARAMETER_JSON_BYTES} bytes")


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-fA-F]{64}", value))


def _safe_segment(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "session")).strip(".-")[:128] or "session"


def _dedupe(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if str(value)))


__all__ = [
    "ALGORITHM_VERSION",
    "AUDIT_SCHEMA_VERSION",
    "MAX_CANDIDATES_PER_FRAME",
    "MAX_FRAMES",
    "MAX_TOTAL_CANDIDATES",
    "MAX_TRAJECTORY_STEPS",
    "SimulationConfig",
    "TargetControlProvider",
    "TargetControlSimulationProvider",
    "score_candidate",
    "select_target",
    "simulate_target_control",
]
