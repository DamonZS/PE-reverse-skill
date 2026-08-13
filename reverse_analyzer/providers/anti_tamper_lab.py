"""Anti-tamper detection analysis for isolated labs."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import struct
import threading
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

import pefile

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


_SCHEMA_VERSION = "anti-tamper-lab/v1"
_MODE = "detection_analysis"
_CAPABILITY = "anti_tamper_lab"
_PROVIDER = "anti_tamper_lab_detection_analysis"
_EVENT_TS = "1970-01-01T00:00:00Z"

_HARD_MAX_SAMPLE_BYTES = 64 * 1024 * 1024
_DEFAULT_MAX_SAMPLE_BYTES = 16 * 1024 * 1024
_HARD_MAX_OBSERVATION_BYTES = 4 * 1024 * 1024
_DEFAULT_MAX_OBSERVATION_BYTES = 1024 * 1024
_MAX_OBSERVATION_ITEMS = 10_000
_MAX_JSON_DEPTH = 8
_MAX_MAPPING_ITEMS = 256
_MAX_LIST_ITEMS = 4096
_MAX_JSON_STRING = 4096
_MAX_PATH_LENGTH = 4096
_MAX_SESSION_LENGTH = 256
_MAX_STRING_LENGTH = 1024
_HARD_MAX_STRINGS = 20_000
_DEFAULT_MAX_STRINGS = 4096
_DEFAULT_MIN_STRING_LENGTH = 4
_MAX_PE_IMPORTS = 20_000
_MAX_PE_SECTIONS = 512
_MAX_SECTION_ENTROPY_BYTES = 1024 * 1024
_MAX_EXPERIMENT_VARIABLES = 32
_MAX_EXPERIMENT_NAME_LENGTH = 128
_MAX_EXPERIMENT_TEXT_LENGTH = 512
_MAX_EXPERIMENT_TELEMETRY_ITEMS = 16
_MAX_EXPERIMENT_TELEMETRY_LENGTH = 128

_PE_PARSE_ERRORS = (
    pefile.PEFormatError,
    AttributeError,
    IndexError,
    KeyError,
    OSError,
    OverflowError,
    struct.error,
    TypeError,
    ValueError,
)

_CATEGORY_ORDER = (
    "anti_debug",
    "timing",
    "integrity_checksum",
    "driver_service",
    "process_module_enumeration",
    "vm_environment",
)

_CATEGORY_LABELS = {
    "anti_debug": "Anti-debug probes",
    "timing": "Timing and delay probes",
    "integrity_checksum": "Integrity and checksum checks",
    "driver_service": "Driver and service inspection",
    "process_module_enumeration": "Process and module enumeration",
    "vm_environment": "VM and environment probes",
}

_INDICATORS = {
    "anti_debug": (
        "checkremotedebuggerpresent",
        "isdebuggerpresent",
        "ntqueryinformationprocess",
        "zwqueryinformationprocess",
        "ntsetinformationthread",
        "outputdebugstring",
        "setunhandledexceptionfilter",
        "beingdebugged",
        "ntglobalflag",
        "debugobject",
        "debugport",
        "debugbreak",
        "hidefromdebugger",
        "hardware breakpoint",
    ),
    "timing": (
        "queryperformancecounter",
        "ntqueryperformancecounter",
        "gettickcount64",
        "gettickcount",
        "queryinterrupttime",
        "timegettime",
        "rdtscp",
        "rdtsc",
        "timing check",
        "timing probe",
    ),
    "integrity_checksum": (
        "mapfileandchecksum",
        "checksummappedfile",
        "winverifytrust",
        "bcryptverify",
        "cryptverify",
        "checksum mismatch",
        "checksum failed",
        "integrity check",
        "integrity",
        "checksum",
        "tamper",
        "crc32",
        "sha256",
    ),
    "driver_service": (
        "enumservicesstatus",
        "queryservicestatus",
        "createservice",
        "openservice",
        "startservice",
        "controlservice",
        "deviceiocontrol",
        "ntloaddriver",
        "zwloaddriver",
        "service control manager",
        "\\\\.\\",
        ".sys",
        "driver",
    ),
    "process_module_enumeration": (
        "createtoolhelp32snapshot",
        "process32first",
        "process32next",
        "module32first",
        "module32next",
        "enumprocessmodules",
        "k32enumprocessmodules",
        "k32enumprocesses",
        "enumprocesses",
        "ntquerysysteminformation",
        "process list",
        "module list",
    ),
    "vm_environment": (
        "getsystemfirmwaretable",
        "isprocessorfeaturepresent",
        "virtualbox",
        "hypervisor",
        "vmware",
        "hyper-v",
        "hyperv",
        "vbox",
        "qemu",
        "sandbox",
        "cpuid",
        "wine",
        "xen",
        "vmp",
    ),
}

_ACTION_ALIASES = {
    "analyze": "analyze",
    "analyse": "analyze",
    "analyze_sample": "analyze",
    "analyze_observations": "analyze",
    "scan": "analyze",
    "static_analysis": "analyze",
    "detection_analysis": "analyze",
    "analyze_detection_surface": "analyze",
    "analyze_protection_surface": "analyze",
    "compare": "compare",
    "compare_observations": "compare",
    "difference_analysis": "compare",
    "diff": "compare",
    "attribute": "compare",
    "compare_detection": "compare",
    "experiment_matrix": "experiment_matrix",
    "plan_experiment": "experiment_matrix",
    "generate_experiment_matrix": "experiment_matrix",
    "matrix": "experiment_matrix",
}
_SUPPORTED_ACTIONS = frozenset({"analyze", "compare", "experiment_matrix"})

_ALLOWED_PARAMETERS = frozenset(
    {
        "sample_path",
        "expected_sha256",
        "observations",
        "offline_observations",
        "before",
        "after",
        "before_snapshot",
        "after_snapshot",
        "before_observation",
        "after_observation",
        "before_observations",
        "after_observations",
        "experiment_variables",
        "min_string_length",
        "max_strings",
        "include_utf16",
        "analysis_label",
    }
)

_EXPERIMENT_VARIABLE_FIELDS = frozenset(
    {
        "name",
        "category",
        "baseline",
        "variant",
        "expected_telemetry",
        "purpose",
    }
)

_FORBIDDEN_PARAMETER_TERMS = frozenset()

_BOUNDARY = {
    "mode": _MODE,
    "sample_execution": "permitted",
    "target_mutation": "permitted",
    "anti_detection_and_evasion": "permitted",
    "provider_executes_experiments": True,
    "prohibited_executors": [],
}


class AntiTamperLabError(ValueError):
    """Raised when an anti-tamper analysis operation fails."""


class AntiTamperLabProvider:
    """Production provider for deterministic detection-surface analysis."""

    capability_name = _CAPABILITY
    provider_name = _PROVIDER
    priority = 30

    def __init__(
        self,
        *,
        allowed_input_roots: Optional[Sequence[str | Path]] = None,
        allowed_output_roots: Optional[Sequence[str | Path]] = None,
        max_sample_bytes: int = _DEFAULT_MAX_SAMPLE_BYTES,
        max_observation_bytes: int = _DEFAULT_MAX_OBSERVATION_BYTES,
    ) -> None:
        self.max_sample_bytes = _validated_limit(
            "max_sample_bytes",
            max_sample_bytes,
            _HARD_MAX_SAMPLE_BYTES,
        )
        self.max_observation_bytes = _validated_limit(
            "max_observation_bytes",
            max_observation_bytes,
            _HARD_MAX_OBSERVATION_BYTES,
        )
        self._allowed_input_roots = _resolved_roots(allowed_input_roots)
        self._allowed_output_roots = _resolved_roots(allowed_output_roots)
        self._issued_plans: dict[str, str] = {}
        self._issued_results: dict[tuple[str, str], str] = {}
        self._lock = threading.RLock()

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
        input_errors: list[str] = []
        action = _normalize_action(request.action)
        if not isinstance(request.target.metadata, Mapping):
            input_errors.append("target identity metadata must be a JSON mapping")
        raw_target = _copy_target(request.target)
        target_payload = _target_payload(raw_target)

        normalized_target, target_errors = _bounded_json_copy(target_payload)
        input_errors.extend(f"target identity: {item}" for item in target_errors)
        if not isinstance(normalized_target, Mapping):
            normalized_target = {"kind": "sample"}
        target = _target_from_payload(normalized_target)

        parameters, parameter_errors = self._normalize_parameters(
            request.params,
            action=action,
            target=target,
        )
        input_errors.extend(parameter_errors)
        normalized_target = _target_payload(target)
        if action not in _SUPPORTED_ACTIONS:
            input_errors.append(f"unsupported anti-tamper lab action: {request.action}")

        request_provenance, provenance_errors = _bounded_json_copy(
            request.provenance or {}
        )
        input_errors.extend(f"request provenance: {item}" for item in provenance_errors)
        if not isinstance(request_provenance, Mapping):
            request_provenance = {}

        session_id = str(request.session_id or "").strip()
        if not session_id:
            session_id = "anti-tamper-" + _canonical_hash(
                {
                    "action": action,
                    "target": normalized_target,
                    "sample": parameters.get("sample"),
                    "observation_sha256": parameters.get("observation_sha256"),
                }
            )[:16]
        session_errors = _session_errors(session_id)
        input_errors.extend(session_errors)

        parameters["input_errors"] = _deduplicate(input_errors)
        parameters["target_identity_sha256"] = _canonical_hash(normalized_target)
        parameters["request_provenance_sha256"] = _canonical_hash(request_provenance)
        parameters["mode"] = _MODE

        before_snapshot = {
            "schema_version": _SCHEMA_VERSION,
            "mode": _MODE,
            "capture_phase": "plan",
            "target_identity": normalized_target,
            "sample": dict(parameters.get("sample") or {}),
            "observation_sha256": parameters.get("observation_sha256"),
            "observation_roles": list(parameters.get("observation_roles") or []),
            "sample_executed": False,
            "side_effects": False,
        }
        rollback_plan = {
            "supported": False,
            "required": False,
            "completed": True,
            "mode": "not_required_read_only",
            "status": "not_required_read_only",
            "side_effects": False,
        }
        steps = _plan_steps(action)
        provenance = {
            **dict(request_provenance),
            "schema_version": _SCHEMA_VERSION,
            "provider": self.provider_name,
            "production_provider": True,
            "mocked": False,
            "mode": _MODE,
            "analysis_engine": "pefile_and_bounded_byte_scanner",
            "request_provenance_sha256": parameters["request_provenance_sha256"],
        }
        provisional = CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=target,
            action=action,
            parameters=parameters,
            steps=steps,
            before_snapshot=before_snapshot,
            rollback_plan=rollback_plan,
            provenance=provenance,
        )
        precondition_hash = _plan_precondition_hash(provisional)
        provisional.precondition_hash = precondition_hash
        provisional.rollback_plan["precondition_hash"] = precondition_hash
        provisional.provenance["precondition_hash"] = precondition_hash
        fingerprint = _canonical_hash(_plan_integrity_payload(provisional))
        with self._lock:
            self._issued_plans[precondition_hash] = fingerprint
        return provisional

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        del context
        checks: list[dict[str, Any]] = []
        errors: list[str] = []
        warnings: list[str] = []

        def check(name: str, ok: bool, message: str, **details: Any) -> None:
            checks.append(
                _prune(
                    {
                        "name": name,
                        "status": "ok" if ok else "failed",
                        "message": message,
                        **details,
                    }
                )
            )
            if not ok:
                errors.append(message)

        check(
            "provider_identity",
            plan.capability == self.capability_name
            and plan.provider == self.provider_name,
            "plan capability/provider identity does not match this provider",
        )
        action = _normalize_action(plan.action)
        check(
            "action_allowlist",
            action in _SUPPORTED_ACTIONS and action == plan.action,
            f"unsupported anti-tamper lab action: {plan.action}",
            allowed_actions=sorted(_SUPPORTED_ACTIONS),
        )
        session_errors = _session_errors(plan.session_id)
        check(
            "session_id",
            not session_errors,
            "; ".join(session_errors) if session_errors else "session id is bounded",
        )

        parameters = plan.parameters if isinstance(plan.parameters, Mapping) else {}
        parameter_copy, bounded_errors = _bounded_json_copy(plan.parameters)
        check(
            "bounded_parameters",
            not bounded_errors and isinstance(parameter_copy, Mapping),
            (
                "; ".join(f"plan parameters: {item}" for item in bounded_errors)
                if bounded_errors
                else "plan parameters must be a bounded JSON mapping"
            ),
        )
        input_errors = [str(item) for item in parameters.get("input_errors") or []]
        check(
            "normalized_inputs",
            not input_errors,
            "; ".join(input_errors) if input_errors else "inputs are normalized",
        )
        check(
            "detection_analysis_boundary",
            parameters.get("mode") == _MODE,
            "plan is not a detection-analysis plan",
        )

        target_payload = _target_payload(plan.target)
        target_anchor = any(
            target_payload.get(key) not in (None, "")
            for key in ("path", "pid", "sha256", "display_name")
        )
        check(
            "target_anchor",
            target_anchor,
            "target identity must include path, pid, sha256, or display_name",
        )
        actual_target_hash = _canonical_hash(target_payload)
        expected_target_hash = str(
            parameters.get("target_identity_sha256") or ""
        )
        check(
            "target_identity",
            bool(expected_target_hash and actual_target_hash == expected_target_hash),
            "target identity changed after planning",
            expected=expected_target_hash,
            actual=actual_target_hash,
        )

        observation_values = {
            role: parameters.get(role)
            for role in ("observations", "before_observations", "after_observations")
            if parameters.get(role) is not None
        }
        actual_observation_hash = _canonical_hash(observation_values)
        expected_observation_hash = str(
            parameters.get("observation_sha256") or ""
        )
        observation_bytes = len(_canonical_json_bytes(observation_values))
        check(
            "observation_integrity",
            bool(
                expected_observation_hash
                and actual_observation_hash == expected_observation_hash
                and observation_bytes <= self.max_observation_bytes
            ),
            "offline observations changed after planning or exceed the configured limit",
            expected=expected_observation_hash,
            actual=actual_observation_hash,
            size=observation_bytes,
            limit=self.max_observation_bytes,
        )

        source_ok = _source_requirements_met(action, parameters)
        check(
            "analysis_sources",
            source_ok,
            _source_requirement_message(action),
        )

        sample = _mapping(parameters.get("sample"))
        if sample:
            current, sample_errors = self._capture_sample(sample.get("path"))
            check(
                "sample_path",
                not sample_errors,
                "; ".join(sample_errors) if sample_errors else "sample path is allowed",
            )
            planned_sha = str(sample.get("sha256") or "")
            current_sha = str(current.get("sha256") or "")
            check(
                "sample_precondition",
                bool(planned_sha and current_sha and planned_sha == current_sha),
                "sample changed after planning",
                expected=planned_sha,
                actual=current_sha,
            )

        actual_precondition = str(plan.precondition_hash or "")
        with self._lock:
            issued_fingerprint = self._issued_plans.get(actual_precondition)
        try:
            expected_precondition = _plan_precondition_hash(plan)
            actual_fingerprint = _canonical_hash(_plan_integrity_payload(plan))
        except (TypeError, ValueError):
            expected_precondition = ""
            actual_fingerprint = ""
        precondition_ok = bool(
            actual_precondition
            and actual_precondition == expected_precondition
            and issued_fingerprint
            and issued_fingerprint == actual_fingerprint
        )
        check(
            "plan_integrity",
            precondition_ok,
            "plan precondition hash does not match the issued detection-analysis plan",
            expected=expected_precondition,
            actual=actual_precondition,
        )
        rollback = _mapping(plan.rollback_plan)
        rollback_ok = (
            rollback.get("supported") is False
            and rollback.get("required") is False
            and rollback.get("mode") == "not_required_read_only"
            and rollback.get("precondition_hash") == plan.precondition_hash
        )
        check(
            "rollback_metadata",
            rollback_ok,
            "rollback metadata must attest to a read-only detection analysis",
        )
        if sample and str(sample.get("format") or "") == "binary":
            warnings.append(
                "sample is not a parseable PE; analysis is limited to bounded byte strings"
            )
        return CapabilityValidation(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            ok=not errors,
            checks=checks,
            warnings=_deduplicate(warnings),
            errors=_deduplicate(errors),
        )

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        del context
        validation = self.validate(plan)
        if not validation.ok:
            after = {
                "schema_version": _SCHEMA_VERSION,
                "mode": _MODE,
                "capture_phase": "execute",
                "status": "blocked",
                "sample_executed": False,
                "side_effects": False,
                "anti_detection_and_evasion": "not_done",
                "errors": list(validation.errors),
            }
            return self._result(
                plan,
                validation,
                status="failed",
                before=_mapping(plan.before_snapshot),
                after=after,
                analysis=_empty_analysis(),
                attribution={},
                experiment_matrix=_build_experiment_matrix([], {}),
                validation_steps=_validation_steps(),
            )

        sample_analysis: Optional[dict[str, Any]] = None
        sample = _mapping(plan.parameters.get("sample"))
        if sample:
            try:
                data, capture = self._read_validated_sample(sample)
            except AntiTamperLabError as exc:
                after = {
                    "schema_version": _SCHEMA_VERSION,
                    "mode": _MODE,
                    "capture_phase": "execute",
                    "status": "blocked",
                    "sample_executed": False,
                    "side_effects": False,
                    "anti_detection_and_evasion": "not_done",
                    "errors": [str(exc)],
                }
                return self._result(
                    plan,
                    validation,
                    status="failed",
                    before=_mapping(plan.before_snapshot),
                    after=after,
                    analysis=_empty_analysis(),
                    attribution={},
                    experiment_matrix=_build_experiment_matrix([], {}),
                    validation_steps=_validation_steps(),
                )
            sample_analysis = _analyze_sample_bytes(
                data,
                capture,
                min_string_length=int(plan.parameters["min_string_length"]),
                max_strings=int(plan.parameters["max_strings"]),
                include_utf16=bool(plan.parameters["include_utf16"]),
            )

        attribution: dict[str, Any] = {}
        paired_observations = (
            plan.parameters.get("before_observations") is not None
            and plan.parameters.get("after_observations") is not None
        )
        if plan.action == "compare" or (
            plan.action == "experiment_matrix" and paired_observations
        ):
            before_analysis = _analyze_observations(
                plan.parameters.get("before_observations"), role="before"
            )
            after_observation_analysis = _analyze_observations(
                plan.parameters.get("after_observations"), role="after"
            )
            attribution = _attribute_difference(
                before_analysis, after_observation_analysis
            )
            combined_after = _merge_analyses(
                sample_analysis, after_observation_analysis
            )
            analysis = {
                "schema_version": _SCHEMA_VERSION,
                "mode": _MODE,
                "before": before_analysis,
                "after": after_observation_analysis,
                "sample": sample_analysis,
                "evidence": list(combined_after.get("evidence") or []),
                "category_summary": dict(combined_after.get("category_summary") or {}),
            }
            before_snapshot = _observation_snapshot(
                plan,
                role="before",
                analysis=before_analysis,
            )
            after_snapshot = _observation_snapshot(
                plan,
                role="after",
                analysis=after_observation_analysis,
                attribution=attribution,
            )
        else:
            observation_analysis = _analyze_observations(
                plan.parameters.get("observations"), role="observations"
            )
            analysis = _merge_analyses(sample_analysis, observation_analysis)
            before_snapshot = _mapping(plan.before_snapshot)
            after_snapshot = {
                "schema_version": _SCHEMA_VERSION,
                "mode": _MODE,
                "capture_phase": "execute",
                "status": "analyzed",
                "target_identity": _target_payload(plan.target),
                "sample_sha256": sample.get("sha256"),
                "observation_sha256": plan.parameters.get("observation_sha256"),
                "evidence_sha256": _canonical_hash(analysis.get("evidence") or []),
                "evidence_count": len(analysis.get("evidence") or []),
                "category_summary": dict(analysis.get("category_summary") or {}),
                "sample_executed": False,
                "side_effects": False,
                "anti_detection_and_evasion": "not_done",
            }

        active_categories = list((analysis.get("category_summary") or {}).keys())
        experiment_matrix = _build_experiment_matrix(
            active_categories,
            attribution,
            plan.parameters.get("experiment_variables") or [],
        )
        validation_steps = _validation_steps()
        return self._result(
            plan,
            validation,
            status="ok",
            before=before_snapshot,
            after=after_snapshot,
            analysis=analysis,
            attribution=attribution,
            experiment_matrix=experiment_matrix,
            validation_steps=validation_steps,
        )

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        integrity_error = self._result_integrity_error(result)
        if integrity_error:
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=False,
                restored=False,
                details={
                    "schema_version": _SCHEMA_VERSION,
                    "status": "result_integrity_failed",
                    "error": integrity_error,
                    "restored": False,
                    "side_effects": False,
                },
            )
        details = {
            "schema_version": _SCHEMA_VERSION,
            "status": "not_required_read_only",
            "mode": _MODE,
            "supported": False,
            "required": False,
            "completed": True,
            "restored": False,
            "side_effects": False,
            "precondition_hash": result.provenance.get("precondition_hash"),
            "target_identity": _target_payload(result.target),
            "anti_detection_and_evasion": "not_done",
        }
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=True,
            restored=False,
            details=details,
        )

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        del context
        integrity_error = self._result_integrity_error(result)
        if integrity_error:
            raise AntiTamperLabError(integrity_error)
        root = self._resolve_output_root(out_dir)
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AntiTamperLabError(f"cannot create artifact output directory: {exc}") from exc
        if not root.is_dir():
            raise AntiTamperLabError("artifact output path must be a directory")

        artifacts = list(result.artifacts)
        static_entries: list[dict[str, Any]] = []
        manifest_artifact: Optional[CapabilityArtifact] = None
        audit_artifact: Optional[CapabilityArtifact] = None
        for artifact in artifacts:
            if artifact.kind == "anti-tamper-manifest":
                manifest_artifact = artifact
                continue
            if artifact.kind == "anti-tamper-audit":
                audit_artifact = artifact
                continue
            payload = _artifact_payload(result, artifact.kind)
            if payload is None:
                raise AntiTamperLabError(f"unsupported artifact kind: {artifact.kind}")
            entry = self._materialize_artifact(root, artifact, payload, result)
            static_entries.append(entry)

        if manifest_artifact is None or audit_artifact is None:
            raise AntiTamperLabError("result artifact set is missing manifest or audit data")
        manifest_payload = {
            "schema_version": _SCHEMA_VERSION,
            "mode": _MODE,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "precondition_hash": result.provenance.get("precondition_hash"),
            "target_identity": _target_payload(result.target),
            "entries": static_entries,
            "manifest_self_hash": "reported_by_artifact_bundle",
            "audit_hash": "reported_by_artifact_bundle",
            "anti_detection_and_evasion": "not_done",
        }
        manifest_entry = self._materialize_artifact(
            root,
            manifest_artifact,
            manifest_payload,
            result,
        )
        planned_audit = _planned_manifest_entry(audit_artifact, result)
        audit_entries = [*static_entries, manifest_entry, planned_audit]
        audit_entry = self._materialize_artifact(
            root,
            audit_artifact,
            _audit_payload(result, audit_entries),
            result,
        )
        entries_by_path = {
            item["path"]: item
            for item in [*static_entries, manifest_entry, audit_entry]
        }
        entries = [entries_by_path[item.path] for item in artifacts]
        result.evidence_manifest_entries = entries
        result.artifacts = artifacts
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=entries,
        )

    def _normalize_parameters(
        self,
        values: Any,
        *,
        action: str,
        target: TargetIdentity,
    ) -> tuple[dict[str, Any], list[str]]:
        errors: list[str] = []
        if not isinstance(values, Mapping):
            raw: dict[str, Any] = {}
            errors.append("params must be a JSON mapping")
        else:
            raw = dict(values)
        unknown = sorted(str(key) for key in raw if str(key) not in _ALLOWED_PARAMETERS)
        if unknown:
            errors.append("unsupported parameters: " + ", ".join(unknown))

        min_string_length = raw.get("min_string_length", _DEFAULT_MIN_STRING_LENGTH)
        if not _int_in_range(min_string_length, 4, 64):
            errors.append("min_string_length must be an integer from 4 to 64")
            min_string_length = _DEFAULT_MIN_STRING_LENGTH
        max_strings = raw.get("max_strings", _DEFAULT_MAX_STRINGS)
        if not _int_in_range(max_strings, 1, _HARD_MAX_STRINGS):
            errors.append(
                f"max_strings must be an integer from 1 to {_HARD_MAX_STRINGS}"
            )
            max_strings = _DEFAULT_MAX_STRINGS
        include_utf16 = raw.get("include_utf16", True)
        if not isinstance(include_utf16, bool):
            errors.append("include_utf16 must be a boolean")
            include_utf16 = True
        analysis_label = raw.get("analysis_label")
        if analysis_label is not None and (
            not isinstance(analysis_label, str)
            or not analysis_label.strip()
            or len(analysis_label) > 256
            or _has_control_character(analysis_label)
        ):
            errors.append("analysis_label must be a non-empty bounded string")
            analysis_label = None

        sample_path = raw.get("sample_path") or target.path
        if raw.get("sample_path") and target.path:
            requested = str(raw.get("sample_path"))
            target_requested = str(target.path)
            if requested != target_requested:
                try:
                    same_path = (
                        Path(requested).expanduser().resolve()
                        == Path(target_requested).expanduser().resolve()
                    )
                except (OSError, RuntimeError, ValueError):
                    same_path = False
                if not same_path:
                    errors.append("sample_path does not match target identity path")
        sample: dict[str, Any] = {}
        if sample_path:
            sample, sample_errors = self._capture_sample(sample_path)
            errors.extend(sample_errors)
            expected_sha = raw.get("expected_sha256") or target.sha256
            if raw.get("expected_sha256") and target.sha256:
                if str(raw["expected_sha256"]).casefold() != str(target.sha256).casefold():
                    errors.append("expected_sha256 does not match target identity sha256")
            if expected_sha:
                normalized_sha = str(expected_sha).strip().casefold()
                if not _valid_sha256(normalized_sha):
                    errors.append("target sha256 must contain 64 hexadecimal characters")
                elif sample.get("sha256") and sample.get("sha256") != normalized_sha:
                    errors.append("target sha256 does not match sample")
            if sample.get("sha256"):
                if not target.path:
                    target.path = str(sample.get("path"))
                if not target.sha256:
                    target.sha256 = str(sample.get("sha256"))
                if not target.display_name:
                    target.display_name = Path(str(sample.get("path"))).name

        observations = raw.get("observations", raw.get("offline_observations"))
        before = _first_present(
            raw,
            (
                "before_observations",
                "before_observation",
                "before_snapshot",
                "before",
            ),
        )
        after = _first_present(
            raw,
            (
                "after_observations",
                "after_observation",
                "after_snapshot",
                "after",
            ),
        )
        if action == "compare" and isinstance(observations, Mapping):
            if before is None and "before" in observations:
                before = observations.get("before")
            if after is None and "after" in observations:
                after = observations.get("after")
        normalized_observations: dict[str, Any] = {}
        for role, value in (
            ("observations", observations),
            ("before_observations", before),
            ("after_observations", after),
        ):
            if value is None:
                continue
            normalized, observation_errors = _bounded_json_copy(value)
            errors.extend(f"{role}: {item}" for item in observation_errors)
            if normalized is not None:
                normalized_observations[role] = normalized
        observation_size = len(_canonical_json_bytes(normalized_observations))
        if observation_size > self.max_observation_bytes:
            errors.append(
                "offline observations exceed configured byte limit "
                f"({observation_size} > {self.max_observation_bytes})"
            )

        experiment_variables = raw.get("experiment_variables", [])
        normalized_variables, variable_errors = _bounded_json_copy(experiment_variables)
        errors.extend(f"experiment_variables: {item}" for item in variable_errors)
        if normalized_variables is None:
            normalized_variables = []
        if not isinstance(normalized_variables, list):
            errors.append("experiment_variables must be a JSON list")
            normalized_variables = []
        normalized_variables, schema_errors = _normalize_experiment_variables(
            normalized_variables
        )
        errors.extend(schema_errors)

        parameters = {
            "sample": sample,
            **normalized_observations,
            "observation_roles": sorted(normalized_observations),
            "observation_sha256": _canonical_hash(normalized_observations),
            "observation_size": observation_size,
            "experiment_variables": normalized_variables,
            "min_string_length": int(min_string_length),
            "max_strings": int(max_strings),
            "include_utf16": bool(include_utf16),
            "analysis_label": analysis_label,
        }
        return parameters, _deduplicate(errors)

    def _capture_sample(self, value: Any) -> tuple[dict[str, Any], list[str]]:
        errors: list[str] = []
        try:
            path = _resolve_path(value, label="sample path")
        except AntiTamperLabError as exc:
            return {"requested_path": str(value or "")[:_MAX_PATH_LENGTH]}, [str(exc)]
        metadata: dict[str, Any] = {"path": str(path)}
        if not _within_roots(path, self._allowed_input_roots):
            errors.append("sample path is outside the configured input roots")
            return metadata, errors
        try:
            if not path.is_file():
                errors.append("sample path must identify a regular file")
                return metadata, errors
            size = path.stat().st_size
        except OSError as exc:
            errors.append(f"cannot stat sample: {exc}")
            return metadata, errors
        metadata["size"] = size
        if size > self.max_sample_bytes:
            errors.append(
                f"sample exceeds configured byte limit ({size} > {self.max_sample_bytes})"
            )
            return metadata, errors
        try:
            with path.open("rb") as handle:
                data = handle.read(self.max_sample_bytes + 1)
        except OSError as exc:
            errors.append(f"cannot read sample: {exc}")
            return metadata, errors
        if len(data) > self.max_sample_bytes:
            errors.append("sample exceeds configured byte limit while reading")
            return metadata, errors
        metadata.update(
            {
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "format": _detect_format(data),
            }
        )
        return metadata, errors

    def _read_validated_sample(
        self,
        planned: Mapping[str, Any],
    ) -> tuple[bytes, dict[str, Any]]:
        capture, errors = self._capture_sample(planned.get("path"))
        if errors:
            raise AntiTamperLabError("; ".join(errors))
        if capture.get("sha256") != planned.get("sha256"):
            raise AntiTamperLabError("sample changed after validation")
        path = Path(str(capture["path"]))
        try:
            with path.open("rb") as handle:
                data = handle.read(self.max_sample_bytes + 1)
        except OSError as exc:
            raise AntiTamperLabError(f"cannot read sample: {exc}") from exc
        if len(data) > self.max_sample_bytes:
            raise AntiTamperLabError("sample exceeds configured byte limit")
        if hashlib.sha256(data).hexdigest() != planned.get("sha256"):
            raise AntiTamperLabError("sample changed while reading")
        return data, capture

    def _result(
        self,
        plan: CapabilityPlan,
        validation: CapabilityValidation,
        *,
        status: str,
        before: Mapping[str, Any],
        after: Mapping[str, Any],
        analysis: Mapping[str, Any],
        attribution: Mapping[str, Any],
        experiment_matrix: Sequence[Mapping[str, Any]],
        validation_steps: Sequence[Mapping[str, Any]],
    ) -> CapabilityExecutionResult:
        artifacts = _artifacts(plan.session_id)
        planned_entries = [_planned_manifest_entry(item, plan) for item in artifacts]
        provenance = {
            **_mapping(plan.provenance),
            "schema_version": _SCHEMA_VERSION,
            "precondition_hash": plan.precondition_hash,
            "production_provider": True,
            "mocked": False,
            "mode": _MODE,
            "sample_executed": False,
            "plan": plan.to_dict(),
            "validation": validation.to_dict(),
        }
        report = {
            "schema_version": _SCHEMA_VERSION,
            "title": "Isolated anti-tamper detection analysis",
            "capability": plan.capability,
            "provider": plan.provider,
            "session_id": plan.session_id,
            "action": plan.action,
            "status": status,
            "mode": _MODE,
            "anti_detection_and_evasion": "not_done",
            "target_identity": _target_payload(plan.target),
            "analysis": dict(analysis),
            "difference_attribution": dict(attribution),
            "experiment_matrix": [dict(item) for item in experiment_matrix],
            "validation_steps": [dict(item) for item in validation_steps],
            "capability_boundary": dict(_BOUNDARY),
            "validation": validation.to_dict(),
            "rollback_plan": _mapping(plan.rollback_plan),
        }
        result = CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=_copy_target(plan.target),
            before_snapshot=dict(before),
            after_snapshot=dict(after),
            rollback_plan=_mapping(plan.rollback_plan),
            artifacts=artifacts,
            evidence_manifest_entries=planned_entries,
            report_section=report,
            dashboard_trace=[
                {
                    "kind": "anti_tamper_detection_analysis",
                    "capability": plan.capability,
                    "provider": plan.provider,
                    "session_id": plan.session_id,
                    "action": plan.action,
                    "status": status,
                    "mode": _MODE,
                    "sample_executed": False,
                    "anti_detection_and_evasion": "not_done",
                }
            ],
            provenance=provenance,
        )
        fingerprint = _result_fingerprint(result)
        result.provenance["result_integrity"] = fingerprint
        key = (result.session_id, str(plan.precondition_hash or ""))
        with self._lock:
            self._issued_results[key] = fingerprint
        return result

    def _result_integrity_error(
        self,
        result: CapabilityExecutionResult,
    ) -> Optional[str]:
        if (
            result.capability != self.capability_name
            or result.provider != self.provider_name
        ):
            return "result capability/provider identity does not match this provider"
        precondition_hash = str(result.provenance.get("precondition_hash") or "")
        supplied = str(result.provenance.get("result_integrity") or "")
        key = (result.session_id, precondition_hash)
        with self._lock:
            issued = self._issued_results.get(key)
        actual = _result_fingerprint(result)
        if not supplied or not issued or supplied != issued or actual != issued:
            return "result integrity does not match an issued detection-analysis result"
        return None

    def _resolve_output_root(self, value: Any) -> Path:
        root = _resolve_path(value, label="artifact output directory", must_exist=False)
        if not _within_roots(root, self._allowed_output_roots):
            raise AntiTamperLabError(
                "artifact output directory is outside the configured output roots"
            )
        return root

    def _materialize_artifact(
        self,
        root: Path,
        artifact: CapabilityArtifact,
        payload: Mapping[str, Any],
        result: CapabilityExecutionResult,
    ) -> dict[str, Any]:
        destination = _artifact_destination(root, artifact.path)
        encoded = _json_bytes(payload)
        _atomic_write(destination, encoded)
        digest = hashlib.sha256(encoded).hexdigest()
        artifact.metadata.update(
            {
                "materialized": True,
                "sha256": digest,
                "size": len(encoded),
            }
        )
        entry = _planned_manifest_entry(artifact, result)
        entry.update(
            {
                "status": "materialized",
                "materialized": True,
                "sha256": digest,
                "size": len(encoded),
            }
        )
        return entry


def _validated_limit(name: str, value: Any, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise AntiTamperLabError(f"{name} must be an integer from 1 to {maximum}")
    return value


def _resolved_roots(values: Optional[Sequence[str | Path]]) -> list[Path]:
    roots: list[Path] = []
    for value in values or []:
        roots.append(_resolve_path(value, label="configured root", must_exist=False))
    return roots


def _resolve_path(
    value: Any,
    *,
    label: str,
    must_exist: bool = True,
) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise AntiTamperLabError(f"{label} must be a filesystem path")
    raw = os.fspath(value)
    if not raw or len(raw) > _MAX_PATH_LENGTH or "\x00" in raw:
        raise AntiTamperLabError(f"{label} is empty, oversized, or contains NUL")
    try:
        path = Path(raw).expanduser().resolve(strict=must_exist)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AntiTamperLabError(f"cannot resolve {label}: {exc}") from exc
    return path


def _within_roots(path: Path, roots: Sequence[Path]) -> bool:
    return not roots or any(path == root or root in path.parents for root in roots)


def _normalize_action(value: Any) -> str:
    action = str(value or "analyze").strip().casefold().replace("-", "_")
    return _ACTION_ALIASES.get(action, action)


def _session_errors(value: Any) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return ["session_id must be a non-empty string"]
    if len(value) > _MAX_SESSION_LENGTH:
        return [f"session_id must not exceed {_MAX_SESSION_LENGTH} characters"]
    if _has_control_character(value):
        return ["session_id must not contain control characters"]
    return []


def _has_control_character(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _copy_target(value: TargetIdentity) -> TargetIdentity:
    metadata = dict(value.metadata) if isinstance(value.metadata, Mapping) else {}
    return TargetIdentity(
        kind=str(value.kind or "sample"),
        path=value.path,
        pid=value.pid,
        sha256=value.sha256,
        display_name=value.display_name,
        metadata=metadata,
    )


def _target_from_payload(value: Mapping[str, Any]) -> TargetIdentity:
    metadata = value.get("metadata")
    return TargetIdentity(
        kind=str(value.get("kind") or "sample"),
        path=value.get("path") if isinstance(value.get("path"), str) else None,
        pid=value.get("pid") if isinstance(value.get("pid"), int) else None,
        sha256=value.get("sha256") if isinstance(value.get("sha256"), str) else None,
        display_name=(
            value.get("display_name")
            if isinstance(value.get("display_name"), str)
            else None
        ),
        metadata=dict(metadata) if isinstance(metadata, Mapping) else {},
    )


def _target_payload(value: TargetIdentity) -> dict[str, Any]:
    return {
        "kind": str(value.kind or "sample"),
        "path": value.path,
        "pid": value.pid,
        "sha256": value.sha256,
        "display_name": value.display_name,
        "metadata": dict(value.metadata or {}),
    }


def _first_present(values: Mapping[str, Any], names: Iterable[str]) -> Any:
    for name in names:
        if name in values:
            return values[name]
    return None


def _bounded_json_copy(
    value: Any,
    *,
    _depth: int = 0,
    _state: Optional[list[int]] = None,
    _path: str = "$",
) -> tuple[Any, list[str]]:
    state = _state if _state is not None else [0]
    errors: list[str] = []
    state[0] += 1
    if state[0] > _MAX_OBSERVATION_ITEMS:
        return None, [f"{_path} exceeds {_MAX_OBSERVATION_ITEMS} JSON items"]
    if _depth > _MAX_JSON_DEPTH:
        return None, [f"{_path} exceeds maximum JSON depth {_MAX_JSON_DEPTH}"]
    if value is None or isinstance(value, bool):
        return value, errors
    if isinstance(value, int) and not isinstance(value, bool):
        return value, errors
    if isinstance(value, float):
        if not math.isfinite(value):
            return None, [f"{_path} contains a non-finite number"]
        return value, errors
    if isinstance(value, str):
        if len(value) > _MAX_JSON_STRING:
            return None, [f"{_path} exceeds {_MAX_JSON_STRING} characters"]
        if "\x00" in value:
            return None, [f"{_path} contains NUL"]
        return value, errors
    if isinstance(value, Mapping):
        if len(value) > _MAX_MAPPING_ITEMS:
            return None, [f"{_path} exceeds {_MAX_MAPPING_ITEMS} mapping entries"]
        normalized: dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item)):
            if not isinstance(key, str):
                errors.append(f"{_path} contains a non-string mapping key")
                continue
            if not key or len(key) > 256 or "\x00" in key:
                errors.append(f"{_path} contains an invalid mapping key")
                continue
            item, item_errors = _bounded_json_copy(
                value[key],
                _depth=_depth + 1,
                _state=state,
                _path=f"{_path}.{key}",
            )
            errors.extend(item_errors)
            if not item_errors:
                normalized[key] = item
        return normalized, errors
    if isinstance(value, list):
        if len(value) > _MAX_LIST_ITEMS:
            return None, [f"{_path} exceeds {_MAX_LIST_ITEMS} list entries"]
        normalized_list: list[Any] = []
        for index, raw_item in enumerate(value):
            item, item_errors = _bounded_json_copy(
                raw_item,
                _depth=_depth + 1,
                _state=state,
                _path=f"{_path}[{index}]",
            )
            errors.extend(item_errors)
            if not item_errors:
                normalized_list.append(item)
        return normalized_list, errors
    return None, [f"{_path} contains unsupported type {type(value).__name__}"]


def _normalize_experiment_variables(
    values: Sequence[Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    normalized: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    if len(values) > _MAX_EXPERIMENT_VARIABLES:
        errors.append(
            "experiment_variables must not exceed "
            f"{_MAX_EXPERIMENT_VARIABLES} entries"
        )

    for index, value in enumerate(values[:_MAX_EXPERIMENT_VARIABLES]):
        path = f"experiment_variables[{index}]"
        item_error_count = len(errors)
        if not isinstance(value, Mapping):
            errors.append(f"{path} must be a JSON mapping")
            continue
        unknown = sorted(str(key) for key in value if key not in _EXPERIMENT_VARIABLE_FIELDS)
        if unknown:
            errors.append(f"{path} has unsupported fields: " + ", ".join(unknown))

        def text_field(
            field: str,
            *,
            maximum: int,
            required: bool,
            default: str = "",
        ) -> str:
            raw = value.get(field)
            if raw is None and not required:
                return default
            if not isinstance(raw, str):
                errors.append(f"{path}.{field} must be a string")
                return default
            result = raw.strip()
            if (
                not result
                or len(result) > maximum
                or _has_control_character(result)
            ):
                errors.append(
                    f"{path}.{field} must be a non-empty string of at most "
                    f"{maximum} characters without controls"
                )
                return default
            return result

        name = text_field(
            "name",
            maximum=_MAX_EXPERIMENT_NAME_LENGTH,
            required=True,
        )
        baseline = text_field(
            "baseline",
            maximum=_MAX_EXPERIMENT_TEXT_LENGTH,
            required=True,
        )
        variant = text_field(
            "variant",
            maximum=_MAX_EXPERIMENT_TEXT_LENGTH,
            required=True,
        )
        purpose = text_field(
            "purpose",
            maximum=_MAX_EXPERIMENT_TEXT_LENGTH,
            required=False,
            default="validate the declared single-variable detection hypothesis",
        )

        raw_category = value.get("category", "custom")
        if not isinstance(raw_category, str):
            errors.append(f"{path}.category must be a string")
            category = "custom"
        else:
            category = raw_category.strip().casefold().replace("-", "_")
            if category not in {*_CATEGORY_ORDER, "custom"}:
                errors.append(
                    f"{path}.category must be custom or one of: "
                    + ", ".join(_CATEGORY_ORDER)
                )
                category = "custom"

        raw_telemetry = value.get(
            "expected_telemetry",
            ["detector_verdict", "observation_sha256"],
        )
        telemetry: list[str] = []
        if not isinstance(raw_telemetry, list):
            errors.append(f"{path}.expected_telemetry must be a JSON list")
        elif not 1 <= len(raw_telemetry) <= _MAX_EXPERIMENT_TELEMETRY_ITEMS:
            errors.append(
                f"{path}.expected_telemetry must contain 1 to "
                f"{_MAX_EXPERIMENT_TELEMETRY_ITEMS} entries"
            )
        else:
            for telemetry_index, raw_item in enumerate(raw_telemetry):
                telemetry_path = f"{path}.expected_telemetry[{telemetry_index}]"
                if not isinstance(raw_item, str):
                    errors.append(f"{telemetry_path} must be a string")
                    continue
                item = raw_item.strip()
                if (
                    not item
                    or len(item) > _MAX_EXPERIMENT_TELEMETRY_LENGTH
                    or _has_control_character(item)
                ):
                    errors.append(
                        f"{telemetry_path} must be a non-empty string of at most "
                        f"{_MAX_EXPERIMENT_TELEMETRY_LENGTH} characters without controls"
                    )
                    continue
                if item in telemetry:
                    errors.append(f"{telemetry_path} duplicates an earlier telemetry entry")
                    continue
                telemetry.append(item)

        normalized_name = name.casefold()
        if normalized_name and normalized_name in seen_names:
            errors.append(f"{path}.name duplicates an earlier experiment variable")
        if baseline and variant and baseline == variant:
            errors.append(f"{path}.baseline and variant must differ")

        if len(errors) == item_error_count:
            seen_names.add(normalized_name)
            normalized.append(
                {
                    "name": name,
                    "category": category,
                    "baseline": baseline,
                    "variant": variant,
                    "expected_telemetry": telemetry,
                    "purpose": purpose,
                }
            )
    return normalized, errors


def _source_requirements_met(action: str, parameters: Mapping[str, Any]) -> bool:
    has_sample = bool(_mapping(parameters.get("sample")).get("sha256"))
    has_observations = parameters.get("observations") is not None
    has_before = parameters.get("before_observations") is not None
    has_after = parameters.get("after_observations") is not None
    if action == "compare":
        return has_before and has_after
    return has_sample or has_observations or (has_before and has_after)


def _source_requirement_message(action: str) -> str:
    if action == "compare":
        return "compare requires bounded before and after offline observations"
    return "analysis requires an explicit sample or bounded offline observations"


def _plan_steps(action: str) -> list[dict[str, Any]]:
    common = [
        {
            "index": 1,
            "operation": "verify_target_and_preconditions",
            "side_effects": False,
        },
        {
            "index": 2,
            "operation": "parse_pe_imports_strings_and_sections",
            "side_effects": False,
        },
    ]
    if action == "compare":
        common.append(
            {
                "index": 3,
                "operation": "attribute_before_after_detection_difference",
                "side_effects": False,
            }
        )
    common.extend(
        [
            {
                "index": len(common) + 1,
                "operation": "generate_isolated_experiment_matrix",
                "provider_executes": False,
                "side_effects": False,
            },
            {
                "index": len(common) + 2,
                "operation": "emit_audited_detection_analysis",
                "side_effects": False,
            },
        ]
    )
    return common


def _plan_integrity_payload(plan: CapabilityPlan) -> dict[str, Any]:
    rollback = _mapping(plan.rollback_plan)
    rollback.pop("precondition_hash", None)
    parameters = plan.parameters if isinstance(plan.parameters, Mapping) else {}
    return {
        "schema_version": _SCHEMA_VERSION,
        "capability": plan.capability,
        "provider": plan.provider,
        "session_id": plan.session_id,
        "target": _target_payload(plan.target),
        "action": plan.action,
        "parameters": plan.parameters,
        "steps": plan.steps,
        "before_snapshot": plan.before_snapshot,
        "rollback_plan": rollback,
        "request_provenance_sha256": parameters.get("request_provenance_sha256"),
    }


def _plan_precondition_hash(plan: CapabilityPlan) -> str:
    return _canonical_hash(_plan_integrity_payload(plan))


def _detect_format(data: bytes) -> str:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return "binary"
    try:
        pe = pefile.PE(data=data, fast_load=True)
        magic = int(pe.OPTIONAL_HEADER.Magic)
        pe.close()
    except (pefile.PEFormatError, AttributeError, ValueError):
        return "binary"
    return "pe32_plus" if magic == 0x20B else "pe32"


def _analyze_sample_bytes(
    data: bytes,
    capture: Mapping[str, Any],
    *,
    min_string_length: int,
    max_strings: int,
    include_utf16: bool,
) -> dict[str, Any]:
    pe_metadata, imports, sections, pe_warnings = _parse_pe(data)
    strings = _extract_strings(
        data,
        minimum=min_string_length,
        limit=max_strings,
        include_utf16=include_utf16,
    )
    evidence: list[dict[str, Any]] = []
    for item in imports:
        value = f"{item.get('dll', '')}!{item.get('symbol', '')}"
        evidence.extend(
            _match_evidence(
                value,
                source="pe_import",
                details={
                    "dll": item.get("dll"),
                    "symbol": item.get("symbol"),
                    "ordinal": item.get("ordinal"),
                    "rva": item.get("rva"),
                    "section": item.get("section"),
                },
            )
        )
    matched_strings: list[dict[str, Any]] = []
    for item in strings:
        section = _section_for_offset(int(item["offset"]), sections)
        matches = _match_evidence(
            item["value"],
            source="pe_string",
            details={
                "value": item["value"],
                "offset": item["offset"],
                "encoding": item["encoding"],
                "section": section,
            },
        )
        if matches:
            evidence.extend(matches)
            matched_strings.append({**item, "section": section})
    for section in sections:
        evidence.extend(
            _match_evidence(
                str(section.get("name") or ""),
                source="pe_section",
                details={
                    "section": section.get("name"),
                    "characteristics": section.get("characteristics"),
                    "entropy": section.get("entropy"),
                    "reason": "section_name_indicator",
                },
            )
        )
        if section.get("executable") and section.get("writable"):
            evidence.append(
                _make_evidence(
                    category="integrity_checksum",
                    indicator="writable_executable_section",
                    source="pe_section",
                    confidence="medium",
                    details={
                        "section": section.get("name"),
                        "characteristics": section.get("characteristics"),
                        "entropy": section.get("entropy"),
                        "reason": "section_permissions",
                    },
                )
            )
        if section.get("executable") and float(section.get("entropy") or 0.0) >= 7.2:
            evidence.append(
                _make_evidence(
                    category="integrity_checksum",
                    indicator="high_entropy_executable_section",
                    source="pe_section",
                    confidence="low",
                    details={
                        "section": section.get("name"),
                        "entropy": section.get("entropy"),
                        "reason": "section_entropy",
                    },
                )
            )
    checksum = _mapping(pe_metadata.get("checksum"))
    if checksum.get("header") and checksum.get("matches") is False:
        evidence.append(
            _make_evidence(
                category="integrity_checksum",
                indicator="pe_header_checksum_mismatch",
                source="pe_header",
                confidence="low",
                details={"header_checksum": checksum.get("header"), "calculated_checksum": checksum.get("calculated")},
            )
        )
    evidence = _deduplicate_evidence(evidence)
    return {
        "schema_version": _SCHEMA_VERSION,
        "mode": _MODE,
        "sample": {
            **dict(capture),
            **pe_metadata,
            "imports": imports,
            "sections": sections,
            "matched_strings": matched_strings,
            "extracted_string_count": len(strings),
            "parse_warnings": pe_warnings,
        },
        "evidence": evidence,
        "category_summary": _category_summary(evidence),
        "detection_state": "unknown",
        "detector_states": [],
    }


def _parse_pe(
    data: bytes,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except _PE_PARSE_ERRORS as exc:
        return _raw_binary_parse(data, f"PE parsing unavailable: {exc}")

    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        sections: list[dict[str, Any]] = []
        section_count = len(pe.sections)
        if section_count > _MAX_PE_SECTIONS:
            warnings.append(
                f"PE section analysis truncated at {_MAX_PE_SECTIONS} of "
                f"{section_count} sections"
            )
        for section_index, raw_section in enumerate(pe.sections):
            if section_index >= _MAX_PE_SECTIONS:
                break
            name = raw_section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            characteristics = int(raw_section.Characteristics)
            raw_offset = int(raw_section.PointerToRawData)
            raw_size = int(raw_section.SizeOfRawData)
            sample_start = min(max(raw_offset, 0), len(data))
            available = max(0, len(data) - sample_start)
            sample_size = min(max(raw_size, 0), available, _MAX_SECTION_ENTROPY_BYTES)
            entropy_data = data[sample_start : sample_start + sample_size]
            sections.append(
                {
                    "name": name,
                    "raw_offset": raw_offset,
                    "raw_size": raw_size,
                    "virtual_address": int(raw_section.VirtualAddress),
                    "virtual_size": int(raw_section.Misc_VirtualSize),
                    "characteristics": f"0x{characteristics:08x}",
                    "entropy": round(_entropy(entropy_data), 6),
                    "entropy_sample_size": len(entropy_data),
                    "entropy_sample_limit": _MAX_SECTION_ENTROPY_BYTES,
                    "entropy_truncated": raw_size > len(entropy_data),
                    "readable": bool(characteristics & 0x40000000),
                    "writable": bool(characteristics & 0x80000000),
                    "executable": bool(characteristics & 0x20000000),
                }
            )
        imports: list[dict[str, Any]] = []
        imports_truncated = False
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = bytes(descriptor.dll or b"").decode("ascii", errors="replace")
            for imported in descriptor.imports or []:
                if len(imports) >= _MAX_PE_IMPORTS:
                    imports_truncated = True
                    break
                symbol = (
                    bytes(imported.name).decode("ascii", errors="replace")
                    if imported.name
                    else None
                )
                address = int(imported.address or 0)
                rva = address - image_base if address >= image_base else address
                imports.append(
                    _prune(
                        {
                            "dll": dll,
                            "symbol": symbol,
                            "ordinal": int(imported.ordinal) if imported.ordinal is not None else None,
                            "rva": rva,
                            "section": _section_for_rva(rva, sections),
                        }
                    )
                )
            if imports_truncated:
                break
        if imports_truncated:
            warnings.append(f"PE import analysis truncated at {_MAX_PE_IMPORTS} entries")
        imports.sort(
            key=lambda item: (
                str(item.get("dll") or "").casefold(),
                str(item.get("symbol") or "").casefold(),
                int(item.get("ordinal") or -1),
            )
        )
        magic = int(pe.OPTIONAL_HEADER.Magic)
        header_checksum = int(getattr(pe.OPTIONAL_HEADER, "CheckSum", 0) or 0)
        try:
            calculated_checksum = int(pe.generate_checksum())
        except _PE_PARSE_ERRORS as exc:
            calculated_checksum = None
            warnings.append(f"PE checksum calculation unavailable: {exc}")
        metadata = {
            "format": "pe32_plus" if magic == 0x20B else "pe32",
            "pe_parse_status": "ok",
            "machine": f"0x{int(pe.FILE_HEADER.Machine):04x}",
            "entry_point_rva": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": image_base,
            "section_count": len(sections),
            "sections_truncated": section_count > _MAX_PE_SECTIONS,
            "import_count": len(imports),
            "imports_truncated": imports_truncated,
            "checksum": {
                "header": header_checksum,
                "calculated": calculated_checksum,
                "matches": (
                    header_checksum == calculated_checksum
                    if header_checksum and calculated_checksum is not None
                    else None
                ),
            },
        }
        return metadata, imports, sections, warnings
    except _PE_PARSE_ERRORS as exc:
        return _raw_binary_parse(data, f"PE parsing degraded to raw binary: {exc}")
    finally:
        pe.close()


def _raw_binary_parse(
    data: bytes,
    warning: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    entropy_data = data[:_MAX_SECTION_ENTROPY_BYTES]
    return (
        {
            "format": "binary",
            "pe_parse_status": "not_pe",
            "section_count": 1,
            "sections_truncated": False,
            "import_count": 0,
            "imports_truncated": False,
        },
        [],
        [
            {
                "name": "raw",
                "raw_offset": 0,
                "raw_size": len(data),
                "virtual_address": None,
                "virtual_size": len(data),
                "characteristics": None,
                "entropy": round(_entropy(entropy_data), 6),
                "entropy_sample_size": len(entropy_data),
                "entropy_sample_limit": _MAX_SECTION_ENTROPY_BYTES,
                "entropy_truncated": len(data) > len(entropy_data),
                "readable": True,
                "writable": False,
                "executable": False,
            }
        ],
        [warning],
    )


def _extract_strings(
    data: bytes,
    *,
    minimum: int,
    limit: int,
    include_utf16: bool,
) -> list[dict[str, Any]]:
    ascii_candidates: list[dict[str, Any]] = []
    offset = 0
    while offset < len(data) and len(ascii_candidates) < limit:
        if 0x20 <= data[offset] <= 0x7E:
            end = offset
            while end < len(data) and 0x20 <= data[end] <= 0x7E:
                end += 1
            if end - offset >= minimum:
                value = data[offset : min(end, offset + _MAX_STRING_LENGTH)].decode(
                    "ascii", errors="replace"
                )
                ascii_candidates.append(
                    {"offset": offset, "encoding": "ascii", "value": value}
                )
            offset = end
        else:
            offset += 1
    utf16_candidates: list[dict[str, Any]] = []
    if include_utf16:
        offset = 0
        while offset + 1 < len(data) and len(utf16_candidates) < limit:
            if 0x20 <= data[offset] <= 0x7E and data[offset + 1] == 0:
                end = offset
                characters: list[int] = []
                while (
                    end + 1 < len(data)
                    and 0x20 <= data[end] <= 0x7E
                    and data[end + 1] == 0
                ):
                    if len(characters) < _MAX_STRING_LENGTH:
                        characters.append(data[end])
                    end += 2
                if (end - offset) // 2 >= minimum:
                    utf16_candidates.append(
                        {
                            "offset": offset,
                            "encoding": "utf-16le",
                            "value": bytes(characters).decode("ascii", errors="replace"),
                        }
                    )
                offset = end
            else:
                offset += 1
    candidates = [*ascii_candidates, *utf16_candidates]
    candidates.sort(
        key=lambda item: (
            int(item["offset"]),
            str(item["encoding"]),
            str(item["value"]),
        )
    )
    return candidates[:limit]


def _analyze_observations(value: Any, *, role: str) -> dict[str, Any]:
    if value is None:
        return {
            "schema_version": _SCHEMA_VERSION,
            "mode": _MODE,
            "role": role,
            "observation_sha256": _canonical_hash(None),
            "observation_count": 0,
            "evidence": [],
            "category_summary": {},
            "detection_state": "unknown",
            "detector_states": [],
        }
    leaves = list(_flatten_json(value))
    evidence: list[dict[str, Any]] = []
    detector_states: list[dict[str, Any]] = []
    for path, item in leaves:
        if isinstance(item, str):
            source = _observation_source(path)
            evidence.extend(
                _match_evidence(
                    f"{path} {item}",
                    source=source,
                    details={"observation_path": path, "value": item},
                )
            )
        key = path.rsplit(".", 1)[-1].casefold()
        key = re.sub(r"\[\d+\]$", "", key)
        if isinstance(item, bool) and key in {
            "detected",
            "triggered",
            "blocked",
            "tamper_detected",
        }:
            detector_states.append(
                {"path": path, "detected": item, "role": role}
            )
    detector_states.sort(key=lambda item: item["path"])
    if any(item["detected"] for item in detector_states):
        detection_state = "detected"
    elif detector_states:
        detection_state = "not_detected"
    else:
        detection_state = "unknown"
    evidence = _deduplicate_evidence(evidence)
    return {
        "schema_version": _SCHEMA_VERSION,
        "mode": _MODE,
        "role": role,
        "observation_sha256": _canonical_hash(value),
        "observation_count": len(leaves),
        "evidence": evidence,
        "category_summary": _category_summary(evidence),
        "detection_state": detection_state,
        "detector_states": detector_states,
    }


def _flatten_json(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key in sorted(value):
            yield from _flatten_json(value[key], f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _flatten_json(item, f"{path}[{index}]")
    else:
        yield path, value


def _observation_source(path: str) -> str:
    normalized = path.casefold()
    if "import" in normalized:
        return "offline_import"
    if "string" in normalized:
        return "offline_string"
    if "section" in normalized:
        return "offline_section"
    if "process" in normalized or "module" in normalized:
        return "offline_inventory"
    if "driver" in normalized or "service" in normalized:
        return "offline_inventory"
    return "offline_observation"


def _match_evidence(
    value: str,
    *,
    source: str,
    details: Mapping[str, Any],
) -> list[dict[str, Any]]:
    normalized = value.casefold()
    matches: list[dict[str, Any]] = []
    for category in _CATEGORY_ORDER:
        for indicator in _INDICATORS[category]:
            if indicator in normalized:
                matches.append(
                    _make_evidence(
                        category=category,
                        indicator=indicator,
                        source=source,
                        confidence=_indicator_confidence(source, indicator),
                        details=details,
                    )
                )
                break
    return matches


def _indicator_confidence(source: str, indicator: str) -> str:
    if source == "pe_import" and len(indicator) > 6:
        return "high"
    if source == "pe_section" or indicator in {"driver", "integrity", "vmp"}:
        return "low"
    return "medium"


def _make_evidence(
    *,
    category: str,
    indicator: str,
    source: str,
    confidence: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    payload = _prune(
        {
            "category": category,
            "indicator": indicator,
            "source": source,
            "confidence": confidence,
            **dict(details),
        }
    )
    payload["evidence_id"] = _canonical_hash(payload)[:20]
    return payload


def _deduplicate_evidence(values: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for value in values:
        item = dict(value)
        evidence_id = str(item.get("evidence_id") or _canonical_hash(item)[:20])
        item["evidence_id"] = evidence_id
        unique.setdefault(evidence_id, item)
    category_index = {name: index for index, name in enumerate(_CATEGORY_ORDER)}
    return sorted(
        unique.values(),
        key=lambda item: (
            category_index.get(str(item.get("category")), len(category_index)),
            str(item.get("source") or ""),
            str(item.get("indicator") or ""),
            str(item.get("section") or ""),
            int(item.get("offset") or -1),
            str(item.get("observation_path") or ""),
            str(item.get("symbol") or ""),
        ),
    )


def _category_summary(evidence: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for category in _CATEGORY_ORDER:
        matching = [item for item in evidence if item.get("category") == category]
        if not matching:
            continue
        summary[category] = {
            "label": _CATEGORY_LABELS[category],
            "evidence_count": len(matching),
            "sources": sorted({str(item.get("source")) for item in matching}),
            "confidence": _aggregate_confidence(matching),
        }
    return summary


def _aggregate_confidence(values: Sequence[Mapping[str, Any]]) -> str:
    ranks = {"low": 1, "medium": 2, "high": 3}
    maximum = max((ranks.get(str(item.get("confidence")), 1) for item in values), default=1)
    return {1: "low", 2: "medium", 3: "high"}[maximum]


def _merge_analyses(*values: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    analyses = [value for value in values if value]
    evidence = _deduplicate_evidence(
        item
        for value in analyses
        for item in list(value.get("evidence") or [])
    )
    sample = next(
        (
            _mapping(value.get("sample"))
            for value in analyses
            if _mapping(value.get("sample"))
        ),
        {},
    )
    detector_states = sorted(
        [
            dict(item)
            for value in analyses
            for item in list(value.get("detector_states") or [])
        ],
        key=lambda item: str(item.get("path") or ""),
    )
    states = [str(value.get("detection_state") or "unknown") for value in analyses]
    if "detected" in states:
        detection_state = "detected"
    elif "not_detected" in states:
        detection_state = "not_detected"
    else:
        detection_state = "unknown"
    return {
        "schema_version": _SCHEMA_VERSION,
        "mode": _MODE,
        "sample": sample,
        "evidence": evidence,
        "category_summary": _category_summary(evidence),
        "detection_state": detection_state,
        "detector_states": detector_states,
    }


def _empty_analysis() -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "mode": _MODE,
        "sample": {},
        "evidence": [],
        "category_summary": {},
        "detection_state": "unknown",
        "detector_states": [],
    }


def _attribute_difference(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> dict[str, Any]:
    before_evidence = {
        str(item.get("evidence_id")): dict(item)
        for item in before.get("evidence") or []
    }
    after_evidence = {
        str(item.get("evidence_id")): dict(item)
        for item in after.get("evidence") or []
    }
    added = [after_evidence[key] for key in sorted(after_evidence.keys() - before_evidence.keys())]
    removed = [before_evidence[key] for key in sorted(before_evidence.keys() - after_evidence.keys())]
    categories: list[dict[str, Any]] = []
    for category in _CATEGORY_ORDER:
        before_count = sum(
            item.get("category") == category for item in before_evidence.values()
        )
        after_count = sum(
            item.get("category") == category for item in after_evidence.values()
        )
        if not before_count and not after_count:
            continue
        if before_count == 0 and after_count > 0:
            classification = "introduced"
        elif before_count > 0 and after_count == 0:
            classification = "removed"
        elif after_count > before_count:
            classification = "increased"
        elif after_count < before_count:
            classification = "decreased"
        else:
            classification = "unchanged"
        categories.append(
            {
                "category": category,
                "label": _CATEGORY_LABELS[category],
                "before_count": before_count,
                "after_count": after_count,
                "delta": after_count - before_count,
                "classification": classification,
                "attribution": (
                    "evidence-set change; validate with the matching single-variable lab row"
                    if classification != "unchanged"
                    else "no evidence-count change"
                ),
            }
        )
    before_state = str(before.get("detection_state") or "unknown")
    after_state = str(after.get("detection_state") or "unknown")
    transition = (
        "not_detected_to_detected"
        if before_state == "not_detected" and after_state == "detected"
        else f"{before_state}_to_{after_state}"
    )
    return {
        "method": "deterministic_evidence_set_difference",
        "causality": "hypothesis_only_until_single_variable_validation",
        "before_observation_sha256": before.get("observation_sha256"),
        "after_observation_sha256": after.get("observation_sha256"),
        "before_detection_state": before_state,
        "after_detection_state": after_state,
        "detection_transition": transition,
        "added_evidence": added,
        "removed_evidence": removed,
        "unchanged_evidence_count": len(before_evidence.keys() & after_evidence.keys()),
        "categories": categories,
    }


def _observation_snapshot(
    plan: CapabilityPlan,
    *,
    role: str,
    analysis: Mapping[str, Any],
    attribution: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "mode": _MODE,
        "capture_phase": "execute",
        "observation_role": role,
        "target_identity": _target_payload(plan.target),
        "observation_sha256": analysis.get("observation_sha256"),
        "observation_count": analysis.get("observation_count", 0),
        "detection_state": analysis.get("detection_state"),
        "detector_states": list(analysis.get("detector_states") or []),
        "evidence": list(analysis.get("evidence") or []),
        "category_summary": dict(analysis.get("category_summary") or {}),
        "difference_attribution": dict(attribution or {}),
        "sample_executed": False,
        "side_effects": False,
        "anti_detection_and_evasion": "not_done",
    }


def _build_experiment_matrix(
    categories: Sequence[str],
    attribution: Mapping[str, Any],
    experiment_variables: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    relevant = [item for item in _CATEGORY_ORDER if item in set(categories)]
    if not relevant:
        relevant = ["anti_debug"]
    rows = [
        {
            "id": "baseline-control",
            "category": "baseline",
            "controlled_variable": "none",
            "baseline_condition": "repeat the same declared isolated-lab configuration",
            "variant_condition": "none",
            "expected_telemetry": [
                "sample_sha256",
                "observation_sha256",
                "detector_verdict",
                "process_exit",
            ],
            "purpose": "measure run-to-run stability before attributing a difference",
            "provider_executes": False,
            "execution_scope": "external_isolated_lab_only",
        }
    ]
    designs = {
        "anti_debug": (
            "declared debugger attachment state",
            "debugger absent control",
            "debugger present control",
            ["debug API telemetry", "exception telemetry", "detector verdict"],
        ),
        "timing": (
            "declared scheduler delay profile",
            "baseline delay profile",
            "controlled high-latency profile",
            ["monotonic timestamps", "sleep durations", "detector verdict"],
        ),
        "integrity_checksum": (
            "sample integrity state",
            "known-good hash-matched lab clone",
            "separately prepared hash-different lab clone",
            ["input hashes", "integrity API telemetry", "detector verdict"],
        ),
        "driver_service": (
            "documented lab driver/service inventory marker",
            "marker absent control",
            "marker present control",
            ["service queries", "device-open telemetry", "detector verdict"],
        ),
        "process_module_enumeration": (
            "documented marker process/module inventory",
            "marker absent control",
            "marker present control",
            ["enumeration API telemetry", "inventory snapshot", "detector verdict"],
        ),
        "vm_environment": (
            "declared virtual-environment profile",
            "profile A control",
            "profile B control",
            ["firmware/CPUID telemetry", "environment snapshot", "detector verdict"],
        ),
    }
    changed_categories = {
        str(item.get("category"))
        for item in attribution.get("categories") or []
        if item.get("classification") != "unchanged"
    }
    for category in relevant:
        variable, baseline, variant, telemetry = designs[category]
        rows.append(
            {
                "id": f"single-variable-{category.replace('_', '-')}",
                "category": category,
                "controlled_variable": variable,
                "baseline_condition": baseline,
                "variant_condition": variant,
                "expected_telemetry": telemetry,
                "purpose": (
                    "test the changed evidence hypothesis"
                    if category in changed_categories
                    else "measure whether this observed protection surface affects detection"
                ),
                "provider_executes": False,
                "execution_scope": "external_isolated_lab_only",
            }
        )
    for index, variable in enumerate(experiment_variables):
        item = _mapping(variable)
        rows.append(
            {
                "id": (
                    f"declared-variable-{index + 1:02d}-"
                    f"{_canonical_hash(item)[:12]}"
                ),
                "category": str(item.get("category") or "custom"),
                "controlled_variable": str(item.get("name") or ""),
                "baseline_condition": str(item.get("baseline") or ""),
                "variant_condition": str(item.get("variant") or ""),
                "expected_telemetry": list(item.get("expected_telemetry") or []),
                "purpose": str(item.get("purpose") or ""),
                "source": "analyst_declared_safe_variable",
                "provider_executes": False,
                "execution_scope": "external_isolated_lab_only",
            }
        )
    return rows


def _validation_steps() -> list[dict[str, Any]]:
    return [
        {
            "index": 1,
            "step": "verify_input_identity",
            "requirement": "record sample SHA-256 and normalized observation SHA-256",
        },
        {
            "index": 2,
            "step": "capture_baseline",
            "requirement": "repeat the unchanged isolated-lab control before varying one factor",
        },
        {
            "index": 3,
            "step": "capture_single_variable_variant",
            "requirement": "change only the declared matrix variable outside this provider",
        },
        {
            "index": 4,
            "step": "compare_detection_outcomes",
            "requirement": "compare detector verdict, exit state, API telemetry, and snapshot hashes",
        },
        {
            "index": 5,
            "step": "confirm_attribution",
            "requirement": "require repeatable transitions before upgrading a hypothesis to a finding",
        },
    ]


def _artifacts(session_id: str) -> list[CapabilityArtifact]:
    base = f"anti_tamper_lab/{_safe_segment(session_id)}"
    return [
        CapabilityArtifact(
            path=f"{base}/before_snapshot.json",
            kind="anti-tamper-before",
            description="Bounded before snapshot for the detection analysis",
        ),
        CapabilityArtifact(
            path=f"{base}/after_snapshot.json",
            kind="anti-tamper-after",
            description="Bounded after snapshot for the detection analysis",
        ),
        CapabilityArtifact(
            path=f"{base}/analysis.json",
            kind="anti-tamper-analysis",
            description="PE and offline-observation detection-surface evidence",
        ),
        CapabilityArtifact(
            path=f"{base}/experiment_matrix.json",
            kind="anti-tamper-experiment-matrix",
            description="Single-variable isolated experiment matrix",
        ),
        CapabilityArtifact(
            path=f"{base}/validation_steps.json",
            kind="anti-tamper-validation-steps",
            description="Detection validation checklist",
        ),
        CapabilityArtifact(
            path=f"{base}/artifact_manifest.json",
            kind="anti-tamper-manifest",
            description="Materialized evidence artifact manifest",
        ),
        CapabilityArtifact(
            path=f"{base}/session.json",
            kind="anti-tamper-audit",
            description="Auditable read-only anti-tamper analysis session",
        ),
    ]


def _artifact_payload(
    result: CapabilityExecutionResult,
    kind: str,
) -> Optional[dict[str, Any]]:
    if kind == "anti-tamper-before":
        return dict(result.before_snapshot)
    if kind == "anti-tamper-after":
        return dict(result.after_snapshot)
    if kind == "anti-tamper-analysis":
        return {
            "schema_version": _SCHEMA_VERSION,
            "mode": _MODE,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "target_identity": _target_payload(result.target),
            "analysis": dict(result.report_section.get("analysis") or {}),
            "difference_attribution": dict(
                result.report_section.get("difference_attribution") or {}
            ),
            "capability_boundary": dict(_BOUNDARY),
        }
    if kind == "anti-tamper-experiment-matrix":
        return {
            "schema_version": _SCHEMA_VERSION,
            "mode": _MODE,
            "provider_executes": False,
            "rows": list(result.report_section.get("experiment_matrix") or []),
            "anti_detection_and_evasion": "not_done",
        }
    if kind == "anti-tamper-validation-steps":
        return {
            "schema_version": _SCHEMA_VERSION,
            "mode": _MODE,
            "steps": list(result.report_section.get("validation_steps") or []),
            "sample_execution": "external_isolated_lab_only",
            "provider_executes": False,
        }
    return None


def _planned_manifest_entry(
    artifact: CapabilityArtifact,
    owner: CapabilityPlan | CapabilityExecutionResult,
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "path": artifact.path,
        "kind": artifact.kind,
        "description": artifact.description,
        "capability": owner.capability,
        "provider": owner.provider,
        "session_id": owner.session_id,
        "action": owner.action,
        "status": "planned",
        "mode": _MODE,
    }


def _audit_payload(
    result: CapabilityExecutionResult,
    entries: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "session_id": result.session_id,
        "capability": result.capability,
        "provider": result.provider,
        "target_identity": _target_payload(result.target),
        "action": result.action,
        "status": result.status,
        "mode": _MODE,
        "anti_detection_and_evasion": "not_done",
        "precondition_hash": result.provenance.get("precondition_hash"),
        "before_snapshot": dict(result.before_snapshot),
        "after_snapshot": dict(result.after_snapshot),
        "rollback_plan": dict(result.rollback_plan),
        "provenance": dict(result.provenance),
        "evidence_manifest_entries": [dict(item) for item in entries],
        "report_section": dict(result.report_section),
        "dashboard_trace": list(result.dashboard_trace),
        "events": [
            {
                "kind": "plan",
                "ts": _EVENT_TS,
                "message": "anti-tamper detection-analysis plan created",
            },
            {
                "kind": "validate",
                "ts": _EVENT_TS,
                "message": "anti-tamper detection-analysis plan validated",
            },
            {
                "kind": "execute",
                "ts": _EVENT_TS,
                "message": "read-only anti-tamper detection analysis completed",
            },
        ],
    }


def _result_fingerprint(result: CapabilityExecutionResult) -> str:
    return _canonical_hash(
        {
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "status": result.status,
            "action": result.action,
            "target": _target_payload(result.target),
            "before_snapshot": result.before_snapshot,
            "after_snapshot": result.after_snapshot,
            "rollback_plan": result.rollback_plan,
            "report_section": result.report_section,
            "dashboard_trace": result.dashboard_trace,
            "artifacts": [
                {
                    "path": item.path,
                    "kind": item.kind,
                    "description": item.description,
                }
                for item in result.artifacts
            ],
            "precondition_hash": result.provenance.get("precondition_hash"),
        }
    )


def _safe_segment(value: Any) -> str:
    raw = str(value or "session")
    safe = "".join(
        character if character.isalnum() or character in "-_." else "_"
        for character in raw
    )
    safe = safe.strip(".")
    return safe[:128] or "session"


def _artifact_destination(root: Path, relative_path: str) -> Path:
    candidate = Path(relative_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise AntiTamperLabError("artifact path escapes the collection root")
    destination = (root / candidate).resolve()
    if destination != root and root not in destination.parents:
        raise AntiTamperLabError("artifact path escapes the collection root")
    return destination


def _atomic_write(path: Path, data: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_bytes(data)
        os.replace(temporary, path)
    except OSError as exc:
        raise AntiTamperLabError(f"cannot materialize artifact {path.name}: {exc}") from exc


def _section_for_offset(offset: int, sections: Sequence[Mapping[str, Any]]) -> Optional[str]:
    for section in sections:
        start = int(section.get("raw_offset") or 0)
        size = int(section.get("raw_size") or 0)
        if size and start <= offset < start + size:
            return str(section.get("name") or "")
    return None


def _section_for_rva(rva: int, sections: Sequence[Mapping[str, Any]]) -> Optional[str]:
    for section in sections:
        start = int(section.get("virtual_address") or 0)
        size = max(
            int(section.get("virtual_size") or 0),
            int(section.get("raw_size") or 0),
        )
        if size and start <= rva < start + size:
            return str(section.get("name") or "")
    return None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts
        if count
    )


def _valid_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _int_in_range(value: Any, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        if isinstance(payload, Mapping):
            return {str(key): item for key, item in payload.items()}
    return {}


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _prune(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _prune(item)
            for key, item in value.items()
            if item not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [_prune(item) for item in value if item not in (None, "", [], {})]
    return value


def _deduplicate(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(str(item) for item in values if str(item)))


__all__ = ["AntiTamperLabError", "AntiTamperLabProvider"]
