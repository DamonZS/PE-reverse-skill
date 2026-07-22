"""Bounded passive protocol capture import and loopback-only replay."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
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
    TargetIdentity,
)
from reverse_analyzer.providers.mock import MockCapabilityProvider
from reverse_analyzer.tools.protocol import protocol_capture


_SCHEMA_VERSION = 1
_CAPTURE = "loopback_tcp_proxy_capture"
_REPLAY = "replay"
_UDP_CAPTURE = "loopback_udp_proxy_capture"
_UDP_REPLAY = "loopback_udp_replay"
_HTTP_CAPTURE = "loopback_http_capture"
_HTTP_REPLAY = "http_fixture_replay"
_PASSIVE_CAPTURE = "passive_capture"
_PASSIVE_IMPORT = "passive_capture_import"
_CAPTURE_ACTIONS = {_CAPTURE, _UDP_CAPTURE, _HTTP_CAPTURE}
_REPLAY_ACTIONS = {_REPLAY, _UDP_REPLAY, _HTTP_REPLAY}
_PASSIVE_ACTIONS = {_PASSIVE_CAPTURE, _PASSIVE_IMPORT}
_SUPPORTED_ACTIONS = _CAPTURE_ACTIONS | _REPLAY_ACTIONS | _PASSIVE_ACTIONS
_ACTION_ALIASES = {
    "capture": _PASSIVE_CAPTURE,
    "capture_import": _PASSIVE_IMPORT,
    "import": _PASSIVE_IMPORT,
    "import_capture": _PASSIVE_IMPORT,
    "offline_capture_import": _PASSIVE_IMPORT,
    "passive_import": _PASSIVE_IMPORT,
    "pcap_import": _PASSIVE_IMPORT,
    "pcapng_import": _PASSIVE_IMPORT,
    "controlled_replay": _REPLAY,
    "loopback_replay": _REPLAY,
    "controlled_http_replay": _HTTP_REPLAY,
    "controlled_http_fixture_replay": _HTTP_REPLAY,
    "http_replay": _HTTP_REPLAY,
    "http_session_replay": _HTTP_REPLAY,
    "loopback_http_replay": _HTTP_REPLAY,
    "replay_http_fixture": _HTTP_REPLAY,
    "http_capture": _HTTP_CAPTURE,
    "http1_capture": _HTTP_CAPTURE,
    "http11_capture": _HTTP_CAPTURE,
    "http_session_capture": _HTTP_CAPTURE,
    "loopback_http1_capture": _HTTP_CAPTURE,
    "loopback_http_proxy_capture": _HTTP_CAPTURE,
}
_DIRECTIONS = {"client_to_server", "server_to_client"}
_REPLAY_FRAME_DIRECTIONS = _DIRECTIONS | {"a_to_b", "b_to_a"}
_SESSION_DIRECTIONS = {"session", "both", "all"}
_REPLAY_MODES = {"frames", "session"}
_REPLAY_TARGET_MODES = {"loopback", "offline_fixture"}
_CAPTURE_SOURCE_FORMATS = {"pcap", "pcapng", "json", "jsonl", "raw"}
_CAPTURE_ADAPTERS = ("dumpcap", "tshark", "tcpdump")
_DEFAULT_DURATION_MS = 2_000
_MAX_DURATION_MS = 30_000
_DEFAULT_SOCKET_TIMEOUT_MS = 500
_MAX_SOCKET_TIMEOUT_MS = 5_000
_DEFAULT_MAX_BYTES = 256 * 1024
_MAX_BYTES = 4 * 1024 * 1024
_DEFAULT_MAX_FRAMES = 256
_MAX_FRAMES = 4_096
_DEFAULT_MAX_CONNECTIONS = 1
_MAX_CONNECTIONS = 16
_DEFAULT_MAX_PACKETS = 4_096
_MAX_PACKETS = 10_000
_DEFAULT_MAX_MESSAGES = 1_024
_MAX_MESSAGES = 4_096
_DEFAULT_MAX_MESSAGE_BYTES = 256 * 1024
_MAX_MESSAGE_BYTES = 1024 * 1024
_DEFAULT_MAX_STREAM_BYTES = 256 * 1024
_MAX_STREAM_BYTES = 1024 * 1024
_DEFAULT_MAX_CORRELATION_MESSAGES = 1_024
_MAX_CORRELATION_MESSAGES = 4_096
_DEFAULT_MAX_REQUEST_RESPONSE_PAIRS = 512
_MAX_REQUEST_RESPONSE_PAIRS = 2_048
_DEFAULT_MAX_HTTP_HEADER_BYTES = 64 * 1024
_MAX_HTTP_HEADER_BYTES = 256 * 1024
_DEFAULT_MAX_HTTP_HEADERS = 100
_MAX_HTTP_HEADERS = 200
_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_MUTATION_PATTERN_BYTES = 4_096
_MAX_TIMING_SCALE = 100.0
_RECV_BYTES = 16 * 1024
_SAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_HTTP_TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_HTTP_METHOD_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_REAL_SOCKET_TYPE = socket.socket


class _HttpNeedMoreData(Exception):
    pass


class ProtocolRuntimeProvider:
    """Import passive evidence or replay bounded flows without remote transmit."""

    capability_name = "protocol_runtime"
    provider_name = "local_loopback_protocol_runtime"
    priority = 10
    supported_actions = (
        _PASSIVE_CAPTURE,
        _PASSIVE_IMPORT,
        _CAPTURE,
        _UDP_CAPTURE,
        _HTTP_CAPTURE,
        _REPLAY,
        _UDP_REPLAY,
        _HTTP_REPLAY,
    )
    safety_boundary = "passive_or_explicit_loopback_only"

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
        action = _normalize_action(request.action)
        if action not in _SUPPORTED_ACTIONS:
            raise ValueError(f"unsupported protocol_runtime action: {request.action!r}")

        session_id = str(request.session_id or "protocol-runtime-session")
        parameters = _normalize_parameters(request, action=action, context=context)
        network_boundary = _network_boundary(parameters)
        target_endpoint = _target_endpoint(parameters)
        tls_audit = _tls_audit_config(parameters.get("tls"))
        traffic_visibility = _tls_traffic_visibility(parameters.get("tls"))
        if action in _PASSIVE_ACTIONS:
            capture_mode = str(parameters.get("capture_mode") or "offline_import")
            if capture_mode == "offline_import":
                source_snapshot = _capture_source_snapshot(
                    parameters.get("capture_source"),
                    max_bytes=int(_mapping(parameters.get("limits")).get("max_bytes") or 0),
                )
                parameters["capture_source_fingerprint"] = source_snapshot.get("fingerprint")
                dependency_probe = {
                    "status": "available",
                    "adapter": "builtin_protocol_parser",
                    "real_adapter": True,
                    "dependency_kind": "builtin",
                }
            else:
                source_snapshot = {}
                dependency_probe = _probe_passive_capture_adapter(
                    str(parameters.get("capture_adapter") or "auto")
                )
                parameters["adapter_probe"] = dependency_probe
            before_snapshot = {
                "session_state": "planned",
                "session": _session_snapshot(
                    session_id,
                    action=action,
                    mode=capture_mode,
                    state="planned",
                ),
                "capture_mode": capture_mode,
                "capture_source": source_snapshot,
                "source_format": parameters.get("source_format"),
                "capture_interface": parameters.get("capture_interface"),
                "dependency_probe": dependency_probe,
                "limits": dict(_mapping(parameters.get("limits"))),
                "network_boundary": network_boundary,
                "network_transmit": False,
                "target_endpoint": {},
            }
            precondition_hash = _passive_precondition_hash(
                parameters,
                request.target,
                action=action,
            )
        elif action in _CAPTURE_ACTIONS:
            before_snapshot = {
                "session_state": "planned",
                "session": _session_snapshot(
                    session_id,
                    action=action,
                    mode="loopback_proxy",
                    state="planned",
                ),
                "transport": parameters["transport"],
                "listen_endpoint": dict(parameters["listen_endpoint"]),
                "upstream_endpoint": dict(parameters["upstream_endpoint"]),
                "listen_endpoint_identity": _endpoint_identity(
                    parameters["listen_endpoint"]
                ),
                "upstream_endpoint_identity": _endpoint_identity(
                    parameters["upstream_endpoint"]
                ),
                "application_protocol": parameters.get("application_protocol"),
                "target_endpoint": target_endpoint,
                "allow_remote": parameters["allow_remote"],
                "tls": tls_audit,
                "traffic_visibility": traffic_visibility,
                "network_boundary": network_boundary,
            }
            precondition_hash = _capture_precondition_hash(
                parameters,
                request.target,
                action=action,
            )
        else:
            source_snapshot = _file_snapshot(parameters["capture_artifact"])
            parameters["capture_artifact_sha256"] = source_snapshot.get("sha256")
            before_snapshot = {
                "session_state": "planned",
                "session": _session_snapshot(
                    session_id,
                    action=action,
                    mode=str(parameters.get("replay_target_mode") or "loopback"),
                    state="planned",
                ),
                "transport": parameters["transport"],
                "capture_artifact": source_snapshot,
                "destination_endpoint": dict(parameters["destination_endpoint"]),
                "destination_endpoint_identity": _endpoint_identity(
                    parameters["destination_endpoint"]
                ),
                "application_protocol": parameters.get("application_protocol"),
                "replay_target_mode": parameters.get("replay_target_mode"),
                "offline_fixture": _public_fixture(parameters.get("offline_fixture")),
                "http_fixture": _public_http_fixture(
                    parameters.get("http_fixture")
                ),
                "target_endpoint": target_endpoint,
                "allow_remote": parameters["allow_remote"],
                "tls": tls_audit,
                "traffic_visibility": traffic_visibility,
                "network_boundary": network_boundary,
            }
            precondition_hash = _replay_precondition_hash(
                parameters,
                request.target,
                source_snapshot.get("sha256"),
                action=action,
            )

        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=action,
            parameters=parameters,
            steps=_plan_steps(action, parameters),
            precondition_hash=precondition_hash,
            before_snapshot=before_snapshot,
            rollback_plan={
                "supported": True,
                "mode": (
                    "terminate_passive_capture_adapter"
                    if action in _PASSIVE_ACTIONS
                    else "close_ephemeral_sockets"
                ),
                "completed": False,
                "idempotent": True,
                "remote_state_restoration_supported": False,
            },
            provenance={
                **dict(request.provenance or {}),
                "provider": self.provider_name,
                "network_boundary": network_boundary,
                "allow_remote": parameters["allow_remote"],
                "remote_access_opt_in": parameters["allow_remote"],
                "target_endpoint": target_endpoint,
                "tls": tls_audit,
                "tls_enabled": bool(tls_audit.get("enabled")),
                "tls_verify": bool(tls_audit.get("verify")),
                "traffic_visibility": traffic_visibility,
                "target_declared_sha256": request.target.sha256,
                "execution_kind": _execution_kind(action, parameters),
                "real_provider": True,
                "mock_provider": False,
                "network_transmit": _plan_network_transmit(action, parameters),
                "dependency_probe": before_snapshot.get("dependency_probe"),
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
        warnings: list[str] = []

        def check(name: str, ok: bool, error: str, **details: Any) -> None:
            checks.append(
                _prune(
                    {
                        "name": name,
                        "status": "ok" if ok else "failed",
                        **details,
                    }
                )
            )
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
            "unsupported protocol runtime action",
            actual=plan.action,
        )
        target_ok = _target_has_identity(plan.target)
        check(
            "target_identity",
            target_ok,
            "target identity must include path, pid, sha256, or display_name",
            target=_target_identity(plan.target),
        )

        limits = _mapping(plan.parameters.get("limits"))
        limit_errors = _limit_errors(limits)
        check(
            "bounded_execution",
            not limit_errors,
            "; ".join(limit_errors) or "execution limits are invalid",
            limits=limits,
        )

        if plan.action in _PASSIVE_ACTIONS:
            self._validate_passive_capture(plan, check, warnings)
        elif plan.action in _CAPTURE_ACTIONS:
            self._validate_capture(plan, check, warnings)
        elif plan.action in _REPLAY_ACTIONS:
            self._validate_replay(plan, check, warnings)

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
        validation = self.validate(plan, context=context)
        if not validation.ok:
            failure_status = _validation_failure_status(plan, validation)
            return self._execution_result(
                plan,
                validation=validation,
                status=failure_status,
                before_snapshot={
                    **dict(plan.before_snapshot or {}),
                    "validation": validation.to_dict(),
                },
                after_snapshot=_empty_after_snapshot(
                    plan,
                    status=failure_status,
                    errors=validation.errors,
                ),
                errors=list(validation.errors),
            )

        if plan.action in _PASSIVE_ACTIONS:
            outcome = self._execute_passive_capture(plan)
        elif plan.action == _HTTP_CAPTURE:
            outcome = self._execute_http_capture(plan, context=context)
        elif plan.action == _CAPTURE:
            outcome = self._execute_capture(plan, context=context)
        elif plan.action == _UDP_CAPTURE:
            outcome = self._execute_udp_capture(plan, context=context)
        elif plan.action == _HTTP_REPLAY:
            outcome = self._execute_http_replay(plan)
        elif str(plan.parameters.get("replay_target_mode") or "loopback") == "offline_fixture":
            outcome = self._execute_offline_replay(plan)
        elif plan.action == _UDP_REPLAY:
            outcome = self._execute_udp_replay(plan)
        else:
            outcome = self._execute_replay(plan)
        return self._execution_result(
            plan,
            validation=validation,
            status=str(outcome["status"]),
            before_snapshot={
                **dict(plan.before_snapshot or {}),
                "validation": validation.to_dict(),
            },
            after_snapshot=dict(outcome["after_snapshot"]),
            errors=list(outcome.get("errors") or []),
        )

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        closed = str(result.after_snapshot.get("session_state") or "") == "closed"
        passive = result.action in _PASSIVE_ACTIONS
        rollback_mode = (
            "terminate_passive_capture_adapter"
            if passive and result.after_snapshot.get("capture_mode") == "adapter"
            else "close_passive_import_session"
            if passive
            else "close_ephemeral_sockets"
        )
        details = {
            "schema_version": _SCHEMA_VERSION,
            "status": "ok" if closed else "failed",
            "mode": rollback_mode,
            "session_id": result.session_id,
            "completed": closed,
            "idempotent": True,
            "restored_remote_state": False,
            "remote_state_restoration_supported": False,
            "reason": (
                "the passive capture/import session was already closed before execute returned"
                if closed and passive
                else "all ephemeral sockets were already closed before execute returned"
                if closed
                else "runtime session did not report a closed state"
            ),
        }
        result.rollback_plan.update(details)
        result.report_section["rollback_plan"] = dict(result.rollback_plan)
        result.report_section["rollback"] = dict(result.rollback_plan)
        result.dashboard_trace.append(
            {
                "kind": "protocol_runtime_rollback",
                "capability": result.capability,
                "provider": result.provider,
                "session_id": result.session_id,
                "status": details["status"],
                "mode": rollback_mode,
                "remote_state_restoration_supported": False,
            }
        )
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=closed,
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
        root = Path(out_dir).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        artifacts = list(result.artifacts or [])
        if not artifacts:
            artifacts.append(_audit_artifact(result.session_id, result.action, result.status))

        entries_by_path = {
            str(item.get("path")): dict(item)
            for item in result.evidence_manifest_entries or []
            if item.get("path")
        }
        manifest_entries: list[dict[str, Any]] = []
        materialized_paths: set[str] = set()
        payload = _artifact_payload(result)
        encoded = (
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        ).encode("utf-8")

        for artifact in artifacts:
            destination = _artifact_destination(root, artifact.path)
            _extended_filesystem_path(destination.parent).mkdir(
                parents=True, exist_ok=True
            )
            # Acceptance workspaces can be deeply nested on Windows. Use the
            # extended-length path form for the atomic write so evidence
            # collection does not fail at the legacy MAX_PATH boundary.
            temporary = destination.with_name(".protocol-runtime.tmp")
            _extended_filesystem_path(temporary).write_bytes(encoded)
            os.replace(
                str(_extended_filesystem_path(temporary)),
                str(_extended_filesystem_path(destination)),
            )
            digest = hashlib.sha256(encoded).hexdigest()
            artifact.metadata.update(
                {
                    "collection_root": str(root),
                    "materialized": True,
                    "sha256": digest,
                    "size": len(encoded),
                }
            )
            entry = entries_by_path.get(
                artifact.path,
                _manifest_entry(
                    artifact,
                    status=result.status,
                    session_id=result.session_id,
                    action=result.action,
                ),
            )
            entry.update(
                {
                    "materialized": True,
                    "sha256": digest,
                    "size": len(encoded),
                }
            )
            manifest_entries.append(entry)
            materialized_paths.add(artifact.path)

        for entry in result.evidence_manifest_entries or []:
            path = str(entry.get("path") or "")
            if path and path not in materialized_paths:
                manifest_entries.append(dict(entry))

        result.artifacts = artifacts
        result.evidence_manifest_entries = manifest_entries
        result.report_section["artifacts"] = [item.to_dict() for item in artifacts]
        result.report_section["evidence_manifest_entries"] = [
            dict(item) for item in manifest_entries
        ]
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=manifest_entries,
        )

    def _validate_passive_capture(
        self,
        plan: CapabilityPlan,
        check: Callable[..., None],
        warnings: list[str],
    ) -> None:
        parameters = plan.parameters
        limits = _mapping(parameters.get("limits"))
        capture_mode = str(parameters.get("capture_mode") or "")
        check(
            "passive_capture_mode",
            capture_mode in {"offline_import", "adapter"},
            "passive capture mode must be offline_import or adapter",
            capture_mode=capture_mode,
        )
        check(
            "no_network_transmit",
            parameters.get("allow_remote") is False,
            "passive capture cannot enable network transmission",
            allow_remote=parameters.get("allow_remote"),
            network_boundary=_network_boundary(parameters),
        )

        if capture_mode == "offline_import":
            snapshot = _capture_source_snapshot(
                parameters.get("capture_source"),
                max_bytes=int(limits.get("max_bytes") or 0),
            )
            source_ok = bool(snapshot.get("is_file")) and not snapshot.get("error")
            check(
                "capture_source",
                source_ok,
                "passive capture source must be a readable local file",
                snapshot=snapshot,
            )
            source_format = _normalize_capture_format(parameters.get("source_format"))
            format_ok = source_format in _CAPTURE_SOURCE_FORMATS or source_format is None
            check(
                "capture_source_format",
                format_ok,
                "capture source format must be PCAP, PCAPNG, JSON, JSONL, or raw",
                source_format=source_format or "auto",
            )
            expected_fingerprint = str(parameters.get("capture_source_fingerprint") or "")
            fingerprint_ok = (
                source_ok
                and bool(expected_fingerprint)
                and expected_fingerprint == str(snapshot.get("fingerprint") or "")
            )
            check(
                "capture_source_precondition",
                fingerprint_ok,
                "passive capture source changed after planning",
                expected=expected_fingerprint,
                actual=snapshot.get("fingerprint"),
            )
            declared_hash = str(plan.provenance.get("target_declared_sha256") or "")
            if declared_hash:
                full_hash = str(snapshot.get("sha256") or "")
                declared_ok = bool(full_hash) and declared_hash.lower() == full_hash.lower()
                check(
                    "declared_capture_hash",
                    declared_ok,
                    (
                        "declared target hash cannot be verified within max_bytes"
                        if snapshot.get("truncated")
                        else "declared target hash does not match the passive capture source"
                    ),
                    expected=declared_hash,
                    actual=full_hash or None,
                    bounded=bool(snapshot.get("truncated")),
                )
            if snapshot.get("truncated"):
                warnings.append(
                    f"capture source will be truncated at max_bytes={int(limits.get('max_bytes') or 0)}"
                )
        elif capture_mode == "adapter":
            interface = str(parameters.get("capture_interface") or "")
            interface_ok, interface_reason = _validate_loopback_capture_interface(interface)
            check(
                "passive_capture_interface",
                interface_ok,
                interface_reason,
                interface=interface,
            )
            adapter = str(parameters.get("capture_adapter") or "auto")
            adapter_ok = adapter == "auto" or adapter in _CAPTURE_ADAPTERS
            check(
                "passive_capture_adapter",
                adapter_ok,
                "capture_adapter must be auto, dumpcap, tshark, or tcpdump",
                adapter=adapter,
            )
            planned_probe = _mapping(parameters.get("adapter_probe"))
            current_probe = _probe_passive_capture_adapter(adapter)
            dependency_ok = current_probe.get("status") == "available"
            check(
                "passive_capture_dependency",
                dependency_ok,
                str(current_probe.get("reason") or "passive capture dependency is unavailable"),
                dependency=current_probe,
            )
            if dependency_ok:
                dependency_stable = _adapter_probe_identity(planned_probe) == _adapter_probe_identity(
                    current_probe
                )
                check(
                    "passive_capture_dependency_precondition",
                    dependency_stable,
                    "passive capture dependency changed after planning",
                    planned=_adapter_probe_identity(planned_probe),
                    current=_adapter_probe_identity(current_probe),
                )

        expected = _passive_precondition_hash(
            parameters,
            plan.target,
            action=plan.action,
        )
        check(
            "precondition_hash",
            bool(plan.precondition_hash) and plan.precondition_hash == expected,
            "passive capture plan parameters no longer match the precondition hash",
            expected=expected,
            actual=plan.precondition_hash,
        )

    def _execute_passive_capture(self, plan: CapabilityPlan) -> dict[str, Any]:
        if str(plan.parameters.get("capture_mode") or "offline_import") == "adapter":
            return self._execute_passive_adapter(plan)
        return self._execute_passive_import(plan)

    def _execute_passive_import(self, plan: CapabilityPlan) -> dict[str, Any]:
        parameters = plan.parameters
        limits = _mapping(parameters.get("limits"))
        source_path = Path(str(parameters.get("capture_source") or ""))
        started = time.monotonic()
        source_before = _capture_source_snapshot(
            source_path,
            max_bytes=int(limits.get("max_bytes") or 0),
        )
        errors: list[str] = []
        if str(source_before.get("fingerprint") or "") != str(
            parameters.get("capture_source_fingerprint") or ""
        ):
            errors.append("passive capture source changed before execution")
            return {
                "status": "failed",
                "after_snapshot": _passive_capture_after(
                    plan,
                    status="failed",
                    source=source_before,
                    capture_result={},
                    dependency_probe={
                        "status": "available",
                        "adapter": "builtin_protocol_parser",
                        "dependency_kind": "builtin",
                        "real_adapter": True,
                    },
                    elapsed_ms=(time.monotonic() - started) * 1_000,
                    errors=errors,
                ),
                "errors": errors,
            }

        capture_result = _run_protocol_capture(source_path, parameters)
        source_after = _capture_source_snapshot(
            source_path,
            max_bytes=int(limits.get("max_bytes") or 0),
        )
        target_drift = (
            _capture_snapshot_identity(source_before)
            != _capture_snapshot_identity(source_after)
        )
        if target_drift:
            errors.append("passive capture source changed while it was imported")
        capture_result, _ = _apply_capture_result_budgets(capture_result, limits)
        status = _passive_capture_status(
            capture_result,
            errors,
            target_drift=target_drift,
        )
        dependency_probe = {
            "status": "available",
            "adapter": "builtin_protocol_parser",
            "dependency_kind": "builtin",
            "real_adapter": True,
        }
        after = _passive_capture_after(
            plan,
            status=status,
            source=source_after,
            capture_result=capture_result,
            dependency_probe=dependency_probe,
            elapsed_ms=(time.monotonic() - started) * 1_000,
            errors=errors,
        )
        return {"status": status, "after_snapshot": after, "errors": errors}

    def _execute_passive_adapter(self, plan: CapabilityPlan) -> dict[str, Any]:
        started = time.monotonic()
        probe = _probe_passive_capture_adapter(
            str(plan.parameters.get("capture_adapter") or "auto")
        )
        if probe.get("status") != "available":
            reason = str(probe.get("reason") or "passive capture dependency is unavailable")
            after = _passive_capture_after(
                plan,
                status="dependency-gated",
                source={},
                capture_result={},
                dependency_probe=probe,
                elapsed_ms=(time.monotonic() - started) * 1_000,
                errors=[reason],
            )
            return {
                "status": "dependency-gated",
                "after_snapshot": after,
                "errors": [reason],
            }

        adapter_outcome = _run_passive_capture_adapter(plan.parameters, probe)
        capture_result = _mapping(adapter_outcome.get("capture_result"))
        limits = _mapping(plan.parameters.get("limits"))
        capture_result, _ = _apply_capture_result_budgets(capture_result, limits)
        errors = list(adapter_outcome.get("errors") or [])
        if adapter_outcome.get("status") == "dependency-gated":
            status = "dependency-gated"
        else:
            status = _passive_capture_status(capture_result, errors, target_drift=False)
            execution = _mapping(adapter_outcome.get("execution"))
            adapter_is_real = (
                probe.get("real_adapter") is True
                and execution.get("started") is True
                and execution.get("real_adapter") is True
                and execution.get("mock_provider") is not True
            )
            if capture_result.get("messages") and not adapter_is_real:
                status = "unavailable"
                errors.append("passive capture adapter execution was not a real local adapter")
        after = _passive_capture_after(
            plan,
            status=status,
            source=_mapping(adapter_outcome.get("source")),
            capture_result=capture_result,
            dependency_probe=probe,
            elapsed_ms=(time.monotonic() - started) * 1_000,
            errors=errors,
            adapter_execution=_mapping(adapter_outcome.get("execution")),
        )
        return {"status": status, "after_snapshot": after, "errors": errors}

    def _execute_offline_replay(self, plan: CapabilityPlan) -> dict[str, Any]:
        parameters = plan.parameters
        limits = _mapping(parameters.get("limits"))
        transport = str(parameters.get("transport") or "tcp")
        replay_mode = str(parameters.get("replay_mode") or "frames")
        started = time.monotonic()
        deadline = started + int(limits.get("duration_ms") or 0) / 1_000.0
        source_path = Path(str(parameters.get("capture_artifact") or ""))
        source_snapshot = _file_snapshot(source_path)
        runtime_frames: list[dict[str, Any]] = []
        errors: list[str] = []
        processed_bytes = 0
        source_frame_count = 0
        limit_reached: Optional[str] = None
        selected: list[dict[str, Any]] = []

        try:
            payload, digest = _load_json_artifact(source_path)
            if digest != parameters.get("capture_artifact_sha256"):
                raise RuntimeError("capture artifact changed before offline replay execution")
            selected = _select_replay_frames(
                payload,
                str(parameters.get("frame_direction") or "client_to_server"),
                transport=transport,
                replay_mode=replay_mode,
            )
            source_frame_count = len(selected)
            timing_state: dict[str, float] = {}
            for source_frame in selected:
                if len(runtime_frames) >= int(limits.get("max_frames") or 0):
                    limit_reached = "max_frames"
                    break
                data = _frame_payload(source_frame)
                if processed_bytes + len(data) > int(limits.get("max_bytes") or 0):
                    limit_reached = "max_bytes"
                    break
                _wait_for_replay_timing(
                    source_frame,
                    state=timing_state,
                    timing_scale=float(parameters.get("timing_scale") or 0.0),
                    deadline=deadline,
                )
                if time.monotonic() >= deadline:
                    limit_reached = "duration_ms"
                    break
                processed_bytes += len(data)
                runtime_frames.append(
                    _runtime_frame(
                        sequence=len(runtime_frames) + 1,
                        connection_id=str(source_frame.get("connection_id") or "offline-fixture"),
                        direction=str(source_frame.get("direction") or "client_to_server"),
                        observed=data,
                        forwarded=data,
                        started=started,
                        transport=transport,
                        source_sequence=source_frame.get("sequence"),
                    )
                )
            errors.extend(_verify_offline_fixture(parameters.get("offline_fixture"), selected))
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(str(exc) or exc.__class__.__name__)

        complete = (
            not errors
            and limit_reached is None
            and source_frame_count > 0
            and len(runtime_frames) == source_frame_count
        )
        if complete:
            status = "ok"
        elif runtime_frames:
            status = "partial"
        else:
            status = "failed"
            if not errors:
                errors.append("no protocol frame bytes were processed by the offline fixture")
        fixture = _public_fixture(parameters.get("offline_fixture"))
        after = {
            "session_state": "closed",
            "session": _session_snapshot(
                plan.session_id,
                action=plan.action,
                mode="offline_fixture",
                state="closed",
            ),
            "side_effects": False,
            "network_transmit": False,
            "transport": transport,
            "capture_artifact": source_snapshot,
            "replay_target_mode": "offline_fixture",
            "offline_fixture": fixture,
            "network_boundary": "offline_fixture_only",
            "replay_mode": replay_mode,
            "source_order_preserved": complete,
            "source_frame_count": source_frame_count,
            "processed_source_frame_count": len(runtime_frames),
            "processed_bytes": processed_bytes,
            "sent_bytes": 0,
            "received_bytes": 0,
            "connection_count": len(
                {str(item.get("connection_id") or "") for item in runtime_frames}
            ),
            "frame_count": len(runtime_frames),
            "frames": runtime_frames,
            "limit_reached": limit_reached,
            "elapsed_ms": round((time.monotonic() - started) * 1_000, 3),
            "errors": _deduplicate(errors),
        }
        return {"status": status, "after_snapshot": _prune(after), "errors": errors}

    def _validate_capture(
        self,
        plan: CapabilityPlan,
        check: Callable[..., None],
        warnings: list[str],
    ) -> None:
        listen = _mapping(plan.parameters.get("listen_endpoint"))
        upstream = _mapping(plan.parameters.get("upstream_endpoint"))
        allow_remote = plan.parameters.get("allow_remote")
        http_capture = plan.action == _HTTP_CAPTURE
        allow_remote_ok = isinstance(allow_remote, bool)
        check(
            "remote_access_opt_in",
            allow_remote_ok,
            "allow_remote must be a boolean",
            allow_remote=allow_remote,
            requested_remote_endpoints=_remote_endpoints((listen, upstream)),
        )
        if http_capture:
            listen_loopback, listen_loopback_reason = _validate_endpoint(
                listen,
                allow_zero_port=True,
                allow_remote=False,
            )
            upstream_loopback, upstream_loopback_reason = _validate_endpoint(
                upstream,
                allow_zero_port=False,
                allow_remote=False,
            )
            check(
                "http_loopback_boundary",
                allow_remote is False and listen_loopback and upstream_loopback,
                (
                    "HTTP capture requires real IPv4/IPv6 loopback endpoints and "
                    "allow_remote=false: "
                    + (listen_loopback_reason or upstream_loopback_reason)
                ).rstrip(": "),
                allow_remote=allow_remote,
                listen_endpoint_identity=_endpoint_identity(listen),
                upstream_endpoint_identity=_endpoint_identity(upstream),
            )
            check(
                "http_application_protocol",
                plan.parameters.get("application_protocol") == "http/1.1",
                "HTTP capture supports only HTTP/1.1",
                application_protocol=plan.parameters.get("application_protocol"),
            )
        listen_ok, listen_reason = _validate_endpoint(
            listen,
            allow_zero_port=True,
            allow_remote=allow_remote is True,
        )
        upstream_ok, upstream_reason = _validate_endpoint(
            upstream,
            allow_zero_port=False,
            allow_remote=allow_remote is True,
        )
        check(
            "listen_endpoint_boundary",
            listen_ok,
            listen_reason,
            endpoint=listen,
        )
        check(
            "upstream_endpoint_boundary",
            upstream_ok,
            upstream_reason,
            endpoint=upstream,
        )
        same_endpoint = (
            listen_ok
            and upstream_ok
            and int(listen.get("port", -1)) != 0
            and _endpoint_key(listen) == _endpoint_key(upstream)
        )
        check(
            "proxy_endpoint_separation",
            not same_endpoint,
            "listen and upstream endpoints must differ",
        )
        mutation, mutation_errors = _validated_mutation(plan.parameters.get("mutation"))
        check(
            "controlled_mutation",
            not mutation_errors,
            "; ".join(mutation_errors) or "mutation specification is invalid",
            mutation=mutation,
        )
        tls = _mapping(plan.parameters.get("tls"))
        tls_errors = _tls_config_errors(
            tls,
            transport=str(plan.parameters.get("transport") or "tcp"),
        )
        check(
            "tls_configuration",
            not tls_errors,
            "; ".join(tls_errors) or "TLS configuration is invalid",
            tls=_tls_audit_config(tls),
        )
        if tls.get("enabled") and not tls.get("verify"):
            warnings.append("TLS certificate verification is explicitly disabled")
        expected = _capture_precondition_hash(
            plan.parameters,
            plan.target,
            action=plan.action,
        )
        check(
            "precondition_hash",
            bool(plan.precondition_hash) and plan.precondition_hash == expected,
            "capture plan parameters no longer match the precondition hash",
            expected=expected,
            actual=plan.precondition_hash,
        )

    def _validate_replay(
        self,
        plan: CapabilityPlan,
        check: Callable[..., None],
        warnings: list[str],
    ) -> None:
        destination = _mapping(plan.parameters.get("destination_endpoint"))
        replay_target_mode = str(plan.parameters.get("replay_target_mode") or "loopback")
        http_replay = plan.action == _HTTP_REPLAY
        check(
            "replay_target_mode",
            replay_target_mode == "loopback" if http_replay else replay_target_mode in _REPLAY_TARGET_MODES,
            (
                "HTTP fixture replay requires a real loopback fixture endpoint"
                if http_replay
                else "replay target mode must be loopback or offline_fixture"
            ),
            replay_target_mode=replay_target_mode,
        )
        transport = str(plan.parameters.get("transport") or "tcp")
        allowed_transports = (
            {"tcp", "udp", "raw", "named_pipe"}
            if replay_target_mode == "offline_fixture"
            else {"tcp", "udp"}
        )
        check(
            "replay_transport",
            transport == "tcp" if http_replay else transport in allowed_transports,
            "loopback replay supports TCP/UDP; offline fixtures also support raw and named_pipe evidence",
            transport=transport,
            replay_target_mode=replay_target_mode,
        )
        allow_remote = plan.parameters.get("allow_remote")
        allow_remote_ok = isinstance(allow_remote, bool)
        check(
            "remote_access_opt_in",
            allow_remote_ok and allow_remote is False,
            "controlled replay never permits allow_remote=true",
            allow_remote=allow_remote,
            requested_remote_endpoints=_remote_endpoints((destination,)),
        )
        if replay_target_mode == "offline_fixture":
            endpoint_ok = not str(destination.get("host") or "") and int(
                destination.get("port") or -1
            ) == -1
            endpoint_reason = (
                "offline fixture replay must not configure a network destination"
                if not endpoint_ok
                else ""
            )
        else:
            endpoint_ok, endpoint_reason = _validate_endpoint(
                destination,
                allow_zero_port=False,
                allow_remote=False,
            )
        check(
            "destination_endpoint_boundary",
            endpoint_ok,
            endpoint_reason,
            endpoint=destination,
            replay_target_mode=replay_target_mode,
        )
        if http_replay:
            check(
                "http_application_protocol",
                plan.parameters.get("application_protocol") == "http/1.1",
                "HTTP fixture replay supports only HTTP/1.1",
                application_protocol=plan.parameters.get("application_protocol"),
            )
            fixture_errors = _http_fixture_errors(plan.parameters.get("http_fixture"))
            check(
                "controlled_http_fixture",
                not fixture_errors,
                "; ".join(fixture_errors) or "controlled HTTP fixture is invalid",
                fixture=_public_http_fixture(plan.parameters.get("http_fixture")),
            )
        fixture_errors = _offline_fixture_errors(plan.parameters.get("offline_fixture"))
        if replay_target_mode == "offline_fixture":
            check(
                "offline_fixture",
                not fixture_errors,
                "; ".join(fixture_errors) or "offline fixture is invalid",
                fixture=_public_fixture(plan.parameters.get("offline_fixture")),
            )
        tls = _mapping(plan.parameters.get("tls"))
        tls_errors = _tls_config_errors(
            tls,
            transport=str(plan.parameters.get("transport") or "tcp"),
        )
        if replay_target_mode == "offline_fixture" and tls.get("enabled"):
            tls_errors.append("offline fixture replay cannot enable TLS sockets")
        check(
            "tls_configuration",
            not tls_errors,
            "; ".join(tls_errors) or "TLS configuration is invalid",
            tls=_tls_audit_config(tls),
        )
        if tls.get("enabled") and not tls.get("verify"):
            warnings.append("TLS certificate verification is explicitly disabled")
        replay_mode = str(plan.parameters.get("replay_mode") or "frames")
        timing_scale = plan.parameters.get("timing_scale")
        replay_settings_ok = (
            replay_mode in _REPLAY_MODES
            and isinstance(timing_scale, (int, float))
            and not isinstance(timing_scale, bool)
            and 0.0 <= float(timing_scale) <= _MAX_TIMING_SCALE
            and (
                replay_mode != "session"
                or str(plan.parameters.get("transport") or "tcp") == "tcp"
            )
        )
        check(
            "replay_settings",
            replay_settings_ok,
            f"replay_mode must be frames (or session for TCP) and timing_scale must be between 0 and {_MAX_TIMING_SCALE:g}",
            replay_mode=replay_mode,
            timing_scale=timing_scale,
        )
        source_path = Path(str(plan.parameters.get("capture_artifact") or ""))
        snapshot = _file_snapshot(source_path)
        source_ok = bool(snapshot.get("is_file")) and not snapshot.get("error")
        check(
            "capture_artifact",
            source_ok,
            "capture artifact must be a readable file",
            snapshot=snapshot,
        )
        size_ok = source_ok and int(snapshot.get("size") or 0) <= _MAX_ARTIFACT_BYTES
        check(
            "capture_artifact_size",
            size_ok,
            f"capture artifact exceeds {_MAX_ARTIFACT_BYTES} bytes",
            maximum=_MAX_ARTIFACT_BYTES,
            actual=snapshot.get("size"),
        )
        planned_artifact_hash = str(
            plan.parameters.get("capture_artifact_sha256") or ""
        )
        artifact_hash_ok = (
            source_ok
            and bool(planned_artifact_hash)
            and str(snapshot.get("sha256") or "").lower()
            == planned_artifact_hash.lower()
        )
        check(
            "capture_artifact_precondition",
            artifact_hash_ok,
            "capture artifact changed after planning",
            expected=planned_artifact_hash,
            actual=snapshot.get("sha256"),
        )
        expected_precondition = _replay_precondition_hash(
            plan.parameters,
            plan.target,
            snapshot.get("sha256"),
            action=plan.action,
        )
        check(
            "replay_plan_precondition",
            bool(plan.precondition_hash)
            and plan.precondition_hash == expected_precondition,
            "replay endpoint, limits, target, or capture input changed after planning",
            expected=expected_precondition,
            actual=plan.precondition_hash,
        )
        declared_hash = str(plan.provenance.get("target_declared_sha256") or "")
        if declared_hash:
            declared_ok = declared_hash.lower() == str(snapshot.get("sha256") or "").lower()
            check(
                "declared_capture_hash",
                declared_ok,
                "declared target hash does not match the capture artifact",
                expected=declared_hash,
                actual=snapshot.get("sha256"),
            )

        artifact_errors: list[str] = []
        selected: list[dict[str, Any]] = []
        if source_ok and size_ok:
            try:
                payload, digest = _load_json_artifact(source_path)
                if digest != snapshot.get("sha256"):
                    artifact_errors.append("capture artifact changed while it was read")
                if http_replay:
                    transactions, http_errors = _http_replay_transactions(
                        payload,
                        _mapping(plan.parameters.get("limits")),
                    )
                    artifact_errors.extend(http_errors)
                    selected = [
                        dict(_mapping(item.get("request"))) for item in transactions
                    ]
                    artifact_errors.extend(
                        _verify_http_fixture_source(
                            plan.parameters.get("http_fixture"),
                            transactions,
                            destination,
                        )
                    )
                else:
                    selected = _select_replay_frames(
                        payload,
                        str(plan.parameters.get("frame_direction") or "client_to_server"),
                        transport=str(plan.parameters.get("transport") or "tcp"),
                        replay_mode=replay_mode,
                    )
                    artifact_errors.extend(
                        _replay_frame_errors(
                            selected,
                            _mapping(plan.parameters.get("limits")),
                            replay_mode=replay_mode,
                            offline=replay_target_mode == "offline_fixture",
                        )
                    )
                    if (
                        replay_target_mode == "loopback"
                        and str(plan.parameters.get("transport") or "tcp") == "tcp"
                    ):
                        artifact_errors.extend(
                            _replay_source_tls_errors(
                                payload,
                                selected,
                                _mapping(plan.parameters.get("tls")),
                            )
                        )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                artifact_errors.append(str(exc) or exc.__class__.__name__)
        else:
            artifact_errors.append("capture artifact is not available for frame validation")
        check(
            "capture_frames",
            not artifact_errors,
            "; ".join(artifact_errors) or "capture frames are invalid",
            selected_frame_count=len(selected),
            direction=plan.parameters.get("frame_direction"),
            replay_mode=replay_mode,
        )
        if replay_target_mode == "loopback" and not bool(plan.parameters.get("verify_echo")):
            warnings.append("replay response equality verification is disabled")

    def _execute_capture(
        self,
        plan: CapabilityPlan,
        *,
        context: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        listen = _mapping(plan.parameters["listen_endpoint"])
        upstream = _mapping(plan.parameters["upstream_endpoint"])
        limits = _mapping(plan.parameters["limits"])
        tls = _mapping(plan.parameters.get("tls"))
        allow_remote = plan.parameters.get("allow_remote") is True
        mutation, _ = _validated_mutation(plan.parameters.get("mutation"))
        deadline = time.monotonic() + int(limits["duration_ms"]) / 1_000.0
        started = time.monotonic()
        frames: list[dict[str, Any]] = []
        connections: list[dict[str, Any]] = []
        errors: list[str] = []
        counters = {
            "observed_bytes": 0,
            "forwarded_bytes": 0,
            "mutation_count": 0,
        }
        limit_reached: Optional[str] = None
        actual_listen: dict[str, Any] = dict(listen)

        listener: Optional[socket.socket] = None
        try:
            listener = _new_socket(str(listen["host"]))
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(_socket_address(str(listen["host"]), int(listen["port"])))
            listener.listen(int(limits["max_connections"]))
            bound = listener.getsockname()
            actual_listen = {"host": str(bound[0]), "port": int(bound[1])}
            if _endpoint_key(actual_listen) == _endpoint_key(upstream):
                raise RuntimeError("resolved proxy listen endpoint equals upstream endpoint")
            callback = context.get("protocol_runtime_ready") if isinstance(context, Mapping) else None
            if callable(callback):
                callback(dict(actual_listen))

            while len(connections) < int(limits["max_connections"]):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    limit_reached = "duration_ms"
                    break
                listener.settimeout(min(0.1, remaining))
                try:
                    client, peer = listener.accept()
                except socket.timeout:
                    continue
                connection_id = f"connection-{len(connections) + 1}"
                connection_record = {
                    "connection_id": connection_id,
                    "peer": _address_mapping(peer),
                    "client_socket_identity": _socket_connection_identity(client),
                    "upstream": dict(upstream),
                    "status": "active",
                    "half_close_events": [],
                }
                connections.append(connection_record)
                upstream_socket: Optional[socket.socket] = None
                try:
                    peer_ok, _ = _endpoint_literal(
                        str(peer[0]),
                        allow_remote=allow_remote,
                    )
                    if not peer_ok:
                        raise RuntimeError("proxy accepted a peer outside the endpoint boundary")
                    upstream_socket = _connect_loopback(
                        upstream,
                        deadline=deadline,
                        timeout_ms=int(limits["socket_timeout_ms"]),
                        allow_remote=allow_remote,
                        tls=tls,
                    )
                    socket_identity = _socket_connection_identity(upstream_socket)
                    tls_evidence = _tls_connection_evidence(
                        upstream_socket,
                        tls,
                    )
                    connection_record["tls"] = tls_evidence
                    connection_record["upstream_socket_identity"] = socket_identity
                    socket_errors = _runtime_socket_identity_errors(
                        upstream_socket,
                        expected_peer=upstream,
                        require_loopback=not allow_remote,
                    )
                    if socket_errors:
                        raise RuntimeError("; ".join(socket_errors))
                    connection_limit = _proxy_connection(
                        client,
                        upstream_socket,
                        connection_id=connection_id,
                        deadline=deadline,
                        limits=limits,
                        mutation=mutation,
                        frames=frames,
                        counters=counters,
                        lifecycle=connection_record["half_close_events"],
                    )
                    if connection_limit:
                        limit_reached = connection_limit
                    connection_record["status"] = "closed"
                except (OSError, RuntimeError) as exc:
                    connection_record["status"] = "failed"
                    connection_record["error"] = str(exc) or exc.__class__.__name__
                    errors.append(connection_record["error"])
                finally:
                    _close_socket(upstream_socket)
                    _close_socket(client)
                if limit_reached:
                    break
        except (OSError, RuntimeError) as exc:
            errors.append(str(exc) or exc.__class__.__name__)
        finally:
            _close_socket(listener)

        if errors and frames:
            status = "partial"
        elif errors:
            status = "failed"
        elif limit_reached and frames:
            status = "partial"
        elif not frames:
            status = "failed"
            errors.append("no loopback protocol frames were captured")
        else:
            status = "ok"
        after = {
            "session_state": "closed",
            "side_effects": bool(frames),
            "transport": "tcp",
            "listen_endpoint": actual_listen,
            "listen_endpoint_identity": _endpoint_identity(actual_listen),
            "upstream_endpoint": dict(upstream),
            "upstream_endpoint_identity": _endpoint_identity(upstream),
            "target_endpoint": dict(upstream),
            "allow_remote": allow_remote,
            "tls": _tls_audit_config(tls),
            "traffic_visibility": _tls_traffic_visibility(tls),
            "network_boundary": _network_boundary(plan.parameters),
            "connection_count": len(connections),
            "connections": connections,
            "frame_count": len(frames),
            "frames": frames,
            "observed_bytes": counters["observed_bytes"],
            "forwarded_bytes": counters["forwarded_bytes"],
            "mutation_count": counters["mutation_count"],
            "limit_reached": limit_reached,
            "elapsed_ms": round((time.monotonic() - started) * 1_000, 3),
            "errors": _deduplicate(errors),
            "real_socket_evidence": bool(connections)
            and all(
                _socket_identity_matches_boundary(
                    _mapping(item.get("upstream_socket_identity")),
                    require_loopback=not allow_remote,
                )
                for item in connections
            ),
        }
        return {"status": status, "after_snapshot": _prune(after), "errors": errors}

    def _execute_http_capture(
        self,
        plan: CapabilityPlan,
        *,
        context: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        raw_outcome = self._execute_capture(plan, context=context)
        after = dict(_mapping(raw_outcome.get("after_snapshot")))
        errors = list(raw_outcome.get("errors") or [])
        evidence = _build_http_capture_evidence(
            list(after.get("frames") or []),
            list(after.get("connections") or []),
            _mapping(plan.parameters.get("limits")),
            raw_limit_reached=after.get("limit_reached"),
        )
        errors.extend(list(evidence.get("errors") or []))
        complete = bool(evidence.get("complete"))
        real_socket_evidence = bool(evidence.get("real_socket_evidence"))
        raw_status = str(raw_outcome.get("status") or "failed")
        if raw_status == "ok" and complete and real_socket_evidence:
            status = "ok"
        elif after.get("frames"):
            status = "partial"
            if not complete and not errors:
                errors.append("HTTP/1.1 request-response evidence is incomplete")
            if not real_socket_evidence:
                errors.append(
                    "HTTP capture did not establish real IPv4/IPv6 loopback socket evidence"
                )
        else:
            status = "failed"
            if not errors:
                errors.append("no HTTP/1.1 bytes were captured")

        messages = list(evidence.get("messages") or [])
        pairs = list(evidence.get("request_response_pairs") or [])
        tunnels = list(evidence.get("connect_tunnels") or [])
        after.update(
            {
                "application_protocol": "http/1.1",
                "capture_kind": "real_loopback_http_proxy",
                "network_transmit": int(after.get("forwarded_bytes") or 0) > 0,
                "message_count": len(messages),
                "messages": messages,
                "http_messages": messages,
                "request_response_pair_count": len(pairs),
                "request_response_pairs": pairs,
                "http_transactions": pairs,
                "http_sessions": list(evidence.get("sessions") or []),
                "connect_tunnel_count": len(tunnels),
                "connect_tunnels": tunnels,
                "http_framing": dict(_mapping(evidence.get("framing"))),
                "integrity": dict(_mapping(evidence.get("integrity"))),
                "real_socket_evidence": real_socket_evidence,
                "real_capture_success": status == "ok" and complete,
                "outcome_class": status,
                "errors": _deduplicate(errors),
            }
        )
        return {
            "status": status,
            "after_snapshot": _prune(after),
            "errors": _deduplicate(errors),
        }

    def _execute_udp_capture(
        self,
        plan: CapabilityPlan,
        *,
        context: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        listen = _mapping(plan.parameters["listen_endpoint"])
        upstream = _mapping(plan.parameters["upstream_endpoint"])
        limits = _mapping(plan.parameters["limits"])
        allow_remote = plan.parameters.get("allow_remote") is True
        mutation, _ = _validated_mutation(plan.parameters.get("mutation"))
        started = time.monotonic()
        deadline = started + int(limits["duration_ms"]) / 1_000.0
        frames: list[dict[str, Any]] = []
        errors: list[str] = []
        counters = {
            "observed_bytes": 0,
            "forwarded_bytes": 0,
            "mutation_count": 0,
        }
        connections_by_peer: OrderedDict[tuple[str, int], dict[str, Any]] = OrderedDict()
        actual_listen: dict[str, Any] = dict(listen)
        limit_reached: Optional[str] = None
        listener: Optional[socket.socket] = None
        upstream_socket: Optional[socket.socket] = None

        try:
            listener = _new_datagram_socket(str(listen["host"]))
            listener.bind(_socket_address(str(listen["host"]), int(listen["port"])))
            bound = listener.getsockname()
            actual_listen = {"host": str(bound[0]), "port": int(bound[1])}
            if _endpoint_key(actual_listen) == _endpoint_key(upstream):
                raise RuntimeError("resolved UDP proxy listen endpoint equals upstream endpoint")
            upstream_socket = _connect_udp_loopback(
                upstream,
                deadline=deadline,
                timeout_ms=int(limits["socket_timeout_ms"]),
                allow_remote=allow_remote,
            )
            callback = context.get("protocol_runtime_ready") if isinstance(context, Mapping) else None
            if callable(callback):
                callback(dict(actual_listen))

            while True:
                if len(frames) >= int(limits["max_frames"]):
                    limit_reached = "max_frames"
                    break
                if counters["observed_bytes"] >= int(limits["max_bytes"]):
                    limit_reached = "max_bytes"
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if frames:
                        break
                    limit_reached = "duration_ms"
                    break
                listener.settimeout(min(0.1, remaining))
                try:
                    observed, peer = listener.recvfrom(65_535)
                except socket.timeout:
                    continue
                peer_mapping = _address_mapping(peer)
                peer_ok, peer_reason = _endpoint_literal(
                    str(peer_mapping.get("host") or ""),
                    allow_remote=allow_remote,
                )
                if not peer_ok:
                    errors.append(peer_reason)
                    continue
                peer_key = _endpoint_key(peer_mapping)
                connection = connections_by_peer.get(peer_key)
                if connection is None:
                    if len(connections_by_peer) >= int(limits["max_connections"]):
                        limit_reached = "max_connections"
                        break
                    connection = {
                        "connection_id": f"datagram-peer-{len(connections_by_peer) + 1}",
                        "peer": peer_mapping,
                        "upstream": dict(upstream),
                        "status": "active",
                        "datagram_count": 0,
                    }
                    connections_by_peer[peer_key] = connection
                if counters["observed_bytes"] + len(observed) > int(limits["max_bytes"]):
                    limit_reached = "max_bytes"
                    break

                forwarded, mutation_record, replacements = _mutate_frame(
                    observed,
                    direction="client_to_server",
                    specification=mutation,
                )
                _send_udp_connected(
                    upstream_socket,
                    forwarded,
                    deadline=deadline,
                    timeout_ms=int(limits["socket_timeout_ms"]),
                )
                counters["observed_bytes"] += len(observed)
                counters["forwarded_bytes"] += len(forwarded)
                counters["mutation_count"] += replacements
                connection["datagram_count"] = int(connection["datagram_count"]) + 1
                frames.append(
                    _runtime_frame(
                        sequence=len(frames) + 1,
                        connection_id=str(connection["connection_id"]),
                        direction="client_to_server",
                        observed=observed,
                        forwarded=forwarded,
                        started=started,
                        transport="udp",
                        mutation=mutation_record,
                    )
                )
                if len(frames) >= int(limits["max_frames"]):
                    limit_reached = "max_frames"
                    break

                upstream_socket.settimeout(
                    min(
                        int(limits["socket_timeout_ms"]) / 1_000.0,
                        max(0.001, deadline - time.monotonic()),
                    )
                )
                try:
                    response = upstream_socket.recv(65_535)
                except socket.timeout:
                    connection["status"] = "partial"
                    connection["error"] = "upstream UDP response timed out"
                    errors.append(str(connection["error"]))
                    continue
                if counters["observed_bytes"] + len(response) > int(limits["max_bytes"]):
                    limit_reached = "max_bytes"
                    break
                returned, response_mutation, response_replacements = _mutate_frame(
                    response,
                    direction="server_to_client",
                    specification=mutation,
                )
                _send_udp_to(
                    listener,
                    returned,
                    peer,
                    deadline=deadline,
                    timeout_ms=int(limits["socket_timeout_ms"]),
                )
                counters["observed_bytes"] += len(response)
                counters["forwarded_bytes"] += len(returned)
                counters["mutation_count"] += response_replacements
                connection["status"] = "closed"
                frames.append(
                    _runtime_frame(
                        sequence=len(frames) + 1,
                        connection_id=str(connection["connection_id"]),
                        direction="server_to_client",
                        observed=response,
                        forwarded=returned,
                        started=started,
                        transport="udp",
                        mutation=response_mutation,
                    )
                )
        except (OSError, RuntimeError) as exc:
            errors.append(str(exc) or exc.__class__.__name__)
        finally:
            _close_socket(upstream_socket)
            _close_socket(listener)

        connections = list(connections_by_peer.values())
        if errors and frames:
            status = "partial"
        elif errors:
            status = "failed"
        elif limit_reached and frames:
            status = "partial"
        elif not frames:
            status = "failed"
            errors.append("no loopback UDP protocol frames were captured")
        else:
            status = "ok"
        after = {
            "session_state": "closed",
            "side_effects": bool(frames),
            "transport": "udp",
            "listen_endpoint": actual_listen,
            "upstream_endpoint": dict(upstream),
            "target_endpoint": dict(upstream),
            "allow_remote": allow_remote,
            "tls": _tls_audit_config(plan.parameters.get("tls")),
            "network_boundary": _network_boundary(plan.parameters),
            "connection_count": len(connections),
            "connections": connections,
            "frame_count": len(frames),
            "frames": frames,
            "observed_bytes": counters["observed_bytes"],
            "forwarded_bytes": counters["forwarded_bytes"],
            "mutation_count": counters["mutation_count"],
            "limit_reached": limit_reached,
            "elapsed_ms": round((time.monotonic() - started) * 1_000, 3),
            "errors": _deduplicate(errors),
        }
        return {"status": status, "after_snapshot": _prune(after), "errors": errors}

    def _execute_replay(self, plan: CapabilityPlan) -> dict[str, Any]:
        if str(plan.parameters.get("replay_mode") or "frames") == "session":
            return self._execute_session_replay(plan)
        destination = _mapping(plan.parameters["destination_endpoint"])
        limits = _mapping(plan.parameters["limits"])
        tls = _mapping(plan.parameters.get("tls"))
        allow_remote = plan.parameters.get("allow_remote") is True
        timing_scale = float(plan.parameters.get("timing_scale") or 0.0)
        started = time.monotonic()
        deadline = started + int(limits["duration_ms"]) / 1_000.0
        frames: list[dict[str, Any]] = []
        connections: list[dict[str, Any]] = []
        errors: list[str] = []
        sent_bytes = 0
        received_bytes = 0
        transmit_attempted = False
        limit_reached: Optional[str] = None
        source_path = Path(str(plan.parameters["capture_artifact"]))
        source_snapshot = _file_snapshot(source_path)
        source_connections: dict[str, dict[str, Any]] = {}

        try:
            payload, digest = _load_json_artifact(source_path)
            if digest != plan.parameters.get("capture_artifact_sha256"):
                raise RuntimeError("capture artifact changed before replay execution")
            selected = _select_replay_frames(
                payload,
                str(plan.parameters["frame_direction"]),
                transport="tcp",
                replay_mode="frames",
            )
            source_connections = _replay_source_connection_map(payload)
            groups = _group_frames(selected)
            for connection_index, (source_connection_id, source_frames) in enumerate(
                groups.items(),
                start=1,
            ):
                if connection_index > int(limits["max_connections"]):
                    limit_reached = "max_connections"
                    break
                runtime_connection_id = f"replay-{connection_index}"
                record = {
                    "connection_id": runtime_connection_id,
                    "source_connection_id": source_connection_id,
                    "destination": dict(destination),
                    "destination_endpoint_identity": _endpoint_identity(destination),
                    "status": "active",
                }
                connections.append(record)
                replay_socket: Optional[socket.socket] = None
                expected_echo = bytearray()
                received = bytearray()
                timing_state: dict[str, float] = {}
                try:
                    replay_socket = _connect_loopback(
                        destination,
                        deadline=deadline,
                        timeout_ms=int(limits["socket_timeout_ms"]),
                        allow_remote=allow_remote,
                        tls=tls,
                    )
                    socket_identity = _socket_connection_identity(replay_socket)
                    tls_evidence = _tls_connection_evidence(replay_socket, tls)
                    record["socket_identity"] = socket_identity
                    record["tls"] = tls_evidence
                    socket_errors = _runtime_socket_identity_errors(
                        replay_socket,
                        expected_peer=destination,
                        require_loopback=True,
                    )
                    tls_binding, tls_binding_errors = _replay_tls_identity_binding(
                        source_connections.get(source_connection_id),
                        tls_evidence,
                    )
                    record["tls_identity_binding"] = tls_binding
                    identity_errors = [*socket_errors, *tls_binding_errors]
                    if identity_errors:
                        raise RuntimeError("; ".join(identity_errors))
                    for source_frame in source_frames:
                        data = _frame_payload(source_frame)
                        if len(frames) >= int(limits["max_frames"]):
                            limit_reached = "max_frames"
                            break
                        if sent_bytes + received_bytes + len(data) > int(limits["max_bytes"]):
                            limit_reached = "max_bytes"
                            break
                        _wait_for_replay_timing(
                            source_frame,
                            state=timing_state,
                            timing_scale=timing_scale,
                            deadline=deadline,
                        )
                        _send_with_deadline(
                            replay_socket,
                            data,
                            deadline=deadline,
                            timeout_ms=int(limits["socket_timeout_ms"]),
                        )
                        sent_bytes += len(data)
                        expected_echo.extend(data)
                        frames.append(
                            _runtime_frame(
                                sequence=len(frames) + 1,
                                connection_id=runtime_connection_id,
                                direction="client_to_server",
                                observed=data,
                                forwarded=data,
                                started=started,
                                source_sequence=source_frame.get("sequence"),
                            )
                        )
                    try:
                        replay_socket.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

                    while not limit_reached and time.monotonic() < deadline:
                        if len(frames) >= int(limits["max_frames"]):
                            limit_reached = "max_frames"
                            break
                        remaining_bytes = int(limits["max_bytes"]) - sent_bytes - received_bytes
                        if remaining_bytes <= 0:
                            limit_reached = "max_bytes"
                            break
                        replay_socket.settimeout(
                            min(
                                int(limits["socket_timeout_ms"]) / 1_000.0,
                                max(0.001, deadline - time.monotonic()),
                            )
                        )
                        try:
                            data = replay_socket.recv(min(_RECV_BYTES, remaining_bytes))
                        except socket.timeout:
                            break
                        if not data:
                            break
                        received.extend(data)
                        received_bytes += len(data)
                        frames.append(
                            _runtime_frame(
                                sequence=len(frames) + 1,
                                connection_id=runtime_connection_id,
                                direction="server_to_client",
                                observed=data,
                                forwarded=data,
                                started=started,
                            )
                        )
                    if bool(plan.parameters.get("verify_echo")) and received != expected_echo:
                        raise RuntimeError("replay response did not equal sent payload bytes")
                    record.update(
                        {
                            "status": "closed",
                            "sent_bytes": len(expected_echo),
                            "received_bytes": len(received),
                            "echo_verified": (
                                received == expected_echo
                                if bool(plan.parameters.get("verify_echo"))
                                else None
                            ),
                        }
                    )
                except (OSError, RuntimeError) as exc:
                    record["status"] = "failed"
                    record["error"] = str(exc) or exc.__class__.__name__
                    errors.append(record["error"])
                finally:
                    _close_socket(replay_socket)
                if limit_reached:
                    break
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(str(exc) or exc.__class__.__name__)

        if errors and sent_bytes:
            status = "partial"
        elif errors:
            status = "failed"
        elif limit_reached and sent_bytes:
            status = "partial"
        elif not sent_bytes:
            status = "failed"
            errors.append("no protocol frame bytes were replayed")
        else:
            status = "ok"
        after = {
            "session_state": "closed",
            "side_effects": sent_bytes > 0,
            "transport": "tcp",
            "capture_artifact": source_snapshot,
            "destination_endpoint": dict(destination),
            "destination_endpoint_identity": _endpoint_identity(destination),
            "target_endpoint": dict(destination),
            "allow_remote": allow_remote,
            "tls": _tls_audit_config(tls),
            "traffic_visibility": _tls_traffic_visibility(tls),
            "network_boundary": _network_boundary(plan.parameters),
            "replay_mode": "frames",
            "timing_scale": timing_scale,
            "connection_count": len(connections),
            "connections": connections,
            "frame_count": len(frames),
            "frames": frames,
            "sent_bytes": sent_bytes,
            "received_bytes": received_bytes,
            "limit_reached": limit_reached,
            "elapsed_ms": round((time.monotonic() - started) * 1_000, 3),
            "errors": _deduplicate(errors),
            "real_socket_evidence": bool(connections)
            and all(
                _socket_identity_is_real_loopback(
                    _mapping(item.get("socket_identity"))
                )
                for item in connections
            ),
        }
        return {"status": status, "after_snapshot": _prune(after), "errors": errors}

    def _execute_session_replay(self, plan: CapabilityPlan) -> dict[str, Any]:
        destination = _mapping(plan.parameters["destination_endpoint"])
        limits = _mapping(plan.parameters["limits"])
        tls = _mapping(plan.parameters.get("tls"))
        allow_remote = plan.parameters.get("allow_remote") is True
        timing_scale = float(plan.parameters.get("timing_scale") or 0.0)
        started = time.monotonic()
        deadline = started + int(limits["duration_ms"]) / 1_000.0
        runtime_frames: list[dict[str, Any]] = []
        records: OrderedDict[str, dict[str, Any]] = OrderedDict()
        sockets: dict[str, socket.socket] = {}
        errors: list[str] = []
        sent_bytes = 0
        received_bytes = 0
        processed_frames = 0
        source_frame_count = 0
        limit_reached: Optional[str] = None
        source_path = Path(str(plan.parameters["capture_artifact"]))
        source_snapshot = _file_snapshot(source_path)
        timing_state: dict[str, float] = {}
        source_connections: dict[str, dict[str, Any]] = {}

        try:
            payload, digest = _load_json_artifact(source_path)
            if digest != plan.parameters.get("capture_artifact_sha256"):
                raise RuntimeError("capture artifact changed before session replay execution")
            selected = _select_replay_frames(
                payload,
                "session",
                transport="tcp",
                replay_mode="session",
            )
            source_connections = _replay_source_connection_map(payload)
            source_frame_count = len(selected)
            for source_frame in selected:
                if len(runtime_frames) >= int(limits["max_frames"]):
                    limit_reached = "max_frames"
                    break
                if time.monotonic() >= deadline:
                    limit_reached = "duration_ms"
                    break
                data = _frame_payload(source_frame)
                if sent_bytes + received_bytes + len(data) > int(limits["max_bytes"]):
                    limit_reached = "max_bytes"
                    break
                source_connection_id = str(source_frame.get("connection_id") or "")
                if source_connection_id not in sockets:
                    if len(sockets) >= int(limits["max_connections"]):
                        limit_reached = "max_connections"
                        break
                    runtime_connection_id = f"session-replay-{len(sockets) + 1}"
                    record = {
                        "connection_id": runtime_connection_id,
                        "source_connection_id": source_connection_id,
                        "destination": dict(destination),
                        "destination_endpoint_identity": _endpoint_identity(destination),
                        "status": "active",
                        "sent_bytes": 0,
                        "received_bytes": 0,
                    }
                    records[source_connection_id] = record
                    replay_socket: Optional[socket.socket] = None
                    try:
                        replay_socket = _connect_loopback(
                            destination,
                            deadline=deadline,
                            timeout_ms=int(limits["socket_timeout_ms"]),
                            allow_remote=allow_remote,
                            tls=tls,
                        )
                        socket_identity = _socket_connection_identity(replay_socket)
                        tls_evidence = _tls_connection_evidence(replay_socket, tls)
                        record["socket_identity"] = socket_identity
                        record["tls"] = tls_evidence
                        socket_errors = _runtime_socket_identity_errors(
                            replay_socket,
                            expected_peer=destination,
                            require_loopback=True,
                        )
                        tls_binding, tls_binding_errors = _replay_tls_identity_binding(
                            source_connections.get(source_connection_id),
                            tls_evidence,
                        )
                        record["tls_identity_binding"] = tls_binding
                        identity_errors = [*socket_errors, *tls_binding_errors]
                        if identity_errors:
                            raise RuntimeError("; ".join(identity_errors))
                    except (OSError, RuntimeError) as exc:
                        _close_socket(replay_socket)
                        record["status"] = "failed"
                        record["error"] = str(exc) or exc.__class__.__name__
                        errors.append(str(record["error"]))
                        break
                    assert replay_socket is not None
                    sockets[source_connection_id] = replay_socket

                replay_socket = sockets[source_connection_id]
                record = records[source_connection_id]
                try:
                    _wait_for_replay_timing(
                        source_frame,
                        state=timing_state,
                        timing_scale=timing_scale,
                        deadline=deadline,
                    )
                    direction = str(source_frame.get("direction") or "")
                    if direction == "client_to_server":
                        _send_with_deadline(
                            replay_socket,
                            data,
                            deadline=deadline,
                            timeout_ms=int(limits["socket_timeout_ms"]),
                        )
                        observed = data
                        sent_bytes += len(data)
                        record["sent_bytes"] = int(record["sent_bytes"]) + len(data)
                    else:
                        observed = _recv_exact_with_deadline(
                            replay_socket,
                            len(data),
                            deadline=deadline,
                            timeout_ms=int(limits["socket_timeout_ms"]),
                        )
                        received_bytes += len(observed)
                        record["received_bytes"] = int(record["received_bytes"]) + len(observed)
                    runtime_frames.append(
                        _runtime_frame(
                            sequence=len(runtime_frames) + 1,
                            connection_id=str(record["connection_id"]),
                            direction=direction,
                            observed=observed,
                            forwarded=observed,
                            started=started,
                            source_sequence=source_frame.get("sequence"),
                        )
                    )
                    if direction == "server_to_client":
                        if len(observed) != len(data):
                            raise RuntimeError(
                                "session replay did not receive the complete expected frame"
                            )
                        if bool(plan.parameters.get("verify_echo")) and observed != data:
                            raise RuntimeError(
                                "session replay response did not match the captured frame"
                            )
                    processed_frames += 1
                except (OSError, RuntimeError) as exc:
                    record["status"] = "failed"
                    record["error"] = str(exc) or exc.__class__.__name__
                    errors.append(str(record["error"]))
                    break
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(str(exc) or exc.__class__.__name__)
        finally:
            for replay_socket in sockets.values():
                _close_socket(replay_socket)

        complete = (
            not errors
            and limit_reached is None
            and source_frame_count > 0
            and processed_frames == source_frame_count
        )
        for record in records.values():
            if record.get("status") == "active":
                record["status"] = "closed" if complete else "partial"
        if complete:
            status = "ok"
        elif runtime_frames or sent_bytes or received_bytes:
            status = "partial"
            if not errors:
                errors.append("session replay did not consume every source frame")
        else:
            status = "failed"
            if not errors:
                errors.append("no protocol frame bytes were replayed")
        after = {
            "session_state": "closed",
            "side_effects": sent_bytes > 0,
            "transport": "tcp",
            "capture_artifact": source_snapshot,
            "destination_endpoint": dict(destination),
            "destination_endpoint_identity": _endpoint_identity(destination),
            "target_endpoint": dict(destination),
            "allow_remote": allow_remote,
            "tls": _tls_audit_config(tls),
            "traffic_visibility": _tls_traffic_visibility(tls),
            "network_boundary": _network_boundary(plan.parameters),
            "replay_mode": "session",
            "timing_scale": timing_scale,
            "source_order_preserved": complete,
            "source_frame_count": source_frame_count,
            "processed_source_frame_count": processed_frames,
            "connection_count": len(records),
            "connections": list(records.values()),
            "frame_count": len(runtime_frames),
            "frames": runtime_frames,
            "sent_bytes": sent_bytes,
            "received_bytes": received_bytes,
            "limit_reached": limit_reached,
            "elapsed_ms": round((time.monotonic() - started) * 1_000, 3),
            "errors": _deduplicate(errors),
            "real_socket_evidence": bool(records)
            and all(
                _socket_identity_is_real_loopback(
                    _mapping(item.get("socket_identity"))
                )
                for item in records.values()
            ),
        }
        return {"status": status, "after_snapshot": _prune(after), "errors": errors}

    def _execute_http_replay(self, plan: CapabilityPlan) -> dict[str, Any]:
        destination = _mapping(plan.parameters.get("destination_endpoint"))
        limits = _mapping(plan.parameters.get("limits"))
        tls = _mapping(plan.parameters.get("tls"))
        fixture = plan.parameters.get("http_fixture")
        started = time.monotonic()
        deadline = started + int(limits.get("duration_ms") or 0) / 1_000.0
        source_path = Path(str(plan.parameters.get("capture_artifact") or ""))
        source_snapshot = _file_snapshot(source_path)
        runtime_frames: list[dict[str, Any]] = []
        runtime_messages: list[dict[str, Any]] = []
        replay_records: list[dict[str, Any]] = []
        connections: list[dict[str, Any]] = []
        errors: list[str] = []
        fail_closed_errors: list[str] = []
        limitations: list[str] = []
        transactions: list[dict[str, Any]] = []
        sent_bytes = 0
        received_bytes = 0
        processed = 0
        limit_reached: Optional[str] = None

        try:
            payload, digest = _load_json_artifact(source_path)
            if digest != plan.parameters.get("capture_artifact_sha256"):
                raise RuntimeError("capture artifact changed before HTTP fixture replay")
            transactions, source_errors = _http_replay_transactions(payload, limits)
            fail_closed_errors.extend(source_errors)
            fail_closed_errors.extend(
                _verify_http_fixture_source(fixture, transactions, destination)
            )
            limitations.extend(_http_replay_limitations(transactions))
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            fail_closed_errors.append(str(exc) or exc.__class__.__name__)

        if not fail_closed_errors:
            for index, transaction in enumerate(transactions, start=1):
                if time.monotonic() >= deadline:
                    limit_reached = "duration_ms"
                    break
                if len(connections) >= int(limits.get("max_connections") or 0):
                    limit_reached = "max_connections"
                    break
                if len(runtime_frames) + 2 > int(limits.get("max_frames") or 0):
                    limit_reached = "max_frames"
                    break
                if not bool(transaction.get("replay_supported")):
                    limitations.extend(list(transaction.get("limitations") or []))
                    continue

                request_message = _mapping(transaction.get("request"))
                expected_response = _mapping(transaction.get("response"))
                request_wire = _http_message_wire(request_message)
                if (
                    sent_bytes
                    + received_bytes
                    + len(request_wire)
                    > int(limits.get("max_bytes") or 0)
                ):
                    limit_reached = "max_bytes"
                    break

                runtime_connection_id = f"http-fixture-replay-{index}"
                connection_record: dict[str, Any] = {
                    "connection_id": runtime_connection_id,
                    "source_connection_id": transaction.get("connection_id"),
                    "destination": dict(destination),
                    "destination_endpoint_identity": _endpoint_identity(destination),
                    "status": "active",
                }
                connections.append(connection_record)
                replay_socket: Optional[socket.socket] = None
                try:
                    replay_socket = _connect_loopback(
                        destination,
                        deadline=deadline,
                        timeout_ms=int(limits.get("socket_timeout_ms") or 0),
                        allow_remote=False,
                        tls=tls,
                    )
                    socket_identity = _socket_connection_identity(replay_socket)
                    tls_evidence = _tls_connection_evidence(replay_socket, tls)
                    connection_record["socket_identity"] = socket_identity
                    connection_record["tls"] = tls_evidence
                    real_socket_errors = _real_loopback_socket_errors(
                        replay_socket,
                        expected_peer=destination,
                    )
                    if real_socket_errors:
                        raise RuntimeError("; ".join(real_socket_errors))
                    connection_fixture_errors = _verify_http_fixture_connection(
                        fixture,
                        socket_identity,
                        tls_evidence,
                        transaction=transaction,
                    )
                    if connection_fixture_errors:
                        fail_closed_errors.extend(connection_fixture_errors)
                        raise RuntimeError("controlled HTTP fixture identity did not match")

                    transmit_attempted = True
                    _send_with_deadline(
                        replay_socket,
                        request_wire,
                        deadline=deadline,
                        timeout_ms=int(limits.get("socket_timeout_ms") or 0),
                    )
                    sent_bytes += len(request_wire)
                    runtime_frames.append(
                        _runtime_frame(
                            sequence=len(runtime_frames) + 1,
                            connection_id=runtime_connection_id,
                            direction="client_to_server",
                            observed=request_wire,
                            forwarded=request_wire,
                            started=started,
                            source_sequence=request_message.get("sequence"),
                        )
                    )
                    actual_responses, pending_tunnel_bytes = _receive_http1_responses(
                        replay_socket,
                        request_method=str(request_message.get("method") or ""),
                        limits=limits,
                        deadline=deadline,
                        timeout_ms=int(limits.get("socket_timeout_ms") or 0),
                        byte_budget=(
                            int(limits.get("max_bytes") or 0)
                            - sent_bytes
                            - received_bytes
                        ),
                        response_frame_budget=(
                            int(limits.get("max_frames") or 0)
                            - len(runtime_frames)
                        ),
                    )
                    if not actual_responses:
                        raise RuntimeError("controlled fixture returned no HTTP/1.1 response")
                    actual_final = actual_responses[-1]
                    for response_index, response in enumerate(actual_responses, start=1):
                        response_wire = _http_message_wire(response)
                        received_bytes += len(response_wire)
                        runtime_frames.append(
                            _runtime_frame(
                                sequence=len(runtime_frames) + 1,
                                connection_id=runtime_connection_id,
                                direction="server_to_client",
                                observed=response_wire,
                                forwarded=response_wire,
                                started=started,
                            )
                        )
                        runtime_message = dict(response)
                        runtime_message.update(
                            {
                                "id": f"{runtime_connection_id}-response-{response_index}",
                                "connection_id": runtime_connection_id,
                                "sequence": len(runtime_messages) + 1,
                                "source_message_id": expected_response.get("id"),
                            }
                        )
                        runtime_messages.append(runtime_message)

                    comparison_errors = _http_response_match_errors(
                        expected_response,
                        actual_final,
                    )
                    comparison_errors.extend(
                        _verify_http_fixture_response(
                            fixture,
                            index=index,
                            actual=actual_final,
                        )
                    )
                    tunnel_frames = list(transaction.get("connect_tunnel_frames") or [])
                    tunnel_half_close_events = list(
                        transaction.get("connect_half_close_events") or []
                    )
                    tunnel_sent = bytearray()
                    tunnel_received = bytearray()
                    runtime_tunnel_frames: list[dict[str, Any]] = []
                    applied_half_close_events: list[dict[str, Any]] = []
                    if str(request_message.get("method") or "").upper() == "CONNECT":
                        if not 200 <= int(actual_final.get("status_code") or 0) < 300:
                            comparison_errors.append(
                                "controlled fixture did not establish the CONNECT tunnel"
                            )
                        if not comparison_errors:
                            for source_frame in tunnel_frames:
                                data = _frame_payload(source_frame)
                                if (
                                    len(runtime_frames) >= int(limits.get("max_frames") or 0)
                                    or sent_bytes + received_bytes + len(data)
                                    > int(limits.get("max_bytes") or 0)
                                ):
                                    raise RuntimeError(
                                        "CONNECT tunnel replay exhausted its frame or byte budget"
                                    )
                                direction = str(source_frame.get("direction") or "")
                                if direction == "client_to_server":
                                    transmit_attempted = True
                                    _send_with_deadline(
                                        replay_socket,
                                        data,
                                        deadline=deadline,
                                        timeout_ms=int(
                                            limits.get("socket_timeout_ms") or 0
                                        ),
                                    )
                                    sent_bytes += len(data)
                                    tunnel_sent.extend(data)
                                elif direction == "server_to_client":
                                    buffered_length = min(
                                        len(data), len(pending_tunnel_bytes)
                                    )
                                    observed = bytes(
                                        pending_tunnel_bytes[:buffered_length]
                                    )
                                    del pending_tunnel_bytes[:buffered_length]
                                    if len(observed) < len(data):
                                        observed += _recv_exact_with_deadline(
                                            replay_socket,
                                            len(data) - len(observed),
                                            deadline=deadline,
                                            timeout_ms=int(
                                                limits.get("socket_timeout_ms") or 0
                                            ),
                                        )
                                    received_bytes += len(observed)
                                    tunnel_received.extend(observed)
                                    if observed != data:
                                        comparison_errors.append(
                                            "controlled CONNECT tunnel response bytes did not match"
                                        )
                                else:
                                    raise ValueError(
                                        "CONNECT tunnel replay frame direction is invalid"
                                    )
                                runtime_tunnel_frame = _runtime_frame(
                                        sequence=len(runtime_frames) + 1,
                                        connection_id=runtime_connection_id,
                                        direction=direction,
                                        observed=data if direction == "client_to_server" else observed,
                                        forwarded=data if direction == "client_to_server" else observed,
                                        started=started,
                                        source_sequence=source_frame.get("source_sequence"),
                                    )
                                runtime_frames.append(runtime_tunnel_frame)
                                runtime_tunnel_frames.append(runtime_tunnel_frame)
                                source_sequence = int(
                                    source_frame.get("source_sequence") or 0
                                )
                                for event in tunnel_half_close_events:
                                    if int(
                                        event.get("after_source_frame_sequence") or 0
                                    ) != source_sequence:
                                        continue
                                    applied_half_close_events.append(
                                        _replay_connect_half_close(
                                            replay_socket,
                                            event,
                                            deadline=deadline,
                                            timeout_ms=int(
                                                limits.get("socket_timeout_ms") or 0
                                            ),
                                        )
                                    )
                            if len(applied_half_close_events) != len(
                                tunnel_half_close_events
                            ):
                                comparison_errors.append(
                                    "CONNECT tunnel half-close events were not fully replayed"
                                )
                            if pending_tunnel_bytes:
                                comparison_errors.append(
                                    "controlled CONNECT tunnel returned trailing bytes"
                                )
                    fixture_verified = not comparison_errors
                    if comparison_errors:
                        fail_closed_errors.extend(comparison_errors)
                    replay_records.append(
                        _prune(
                            {
                                "id": f"http-replay-transaction-{index}",
                                "connection_id": runtime_connection_id,
                                "source_connection_id": transaction.get("connection_id"),
                                "source_pair_id": _mapping(transaction.get("pair")).get(
                                    "id"
                                ),
                                "request_message_id": request_message.get("id"),
                                "expected_response_message_id": expected_response.get("id"),
                                "actual_response_message_id": runtime_messages[-1].get("id"),
                                "request_wire_sha256": request_message.get("wire_sha256"),
                                "expected_response_wire_sha256": expected_response.get(
                                    "wire_sha256"
                                ),
                                "actual_response_wire_sha256": actual_final.get(
                                    "wire_sha256"
                                ),
                                "expected_response_body_sha256": expected_response.get(
                                    "body_sha256"
                                ),
                                "actual_response_body_sha256": actual_final.get(
                                    "body_sha256"
                                ),
                                "connect_authority": _mapping(
                                    transaction.get("connect_tunnel")
                                ).get("authority"),
                                "connect_tunnel_frame_count": len(tunnel_frames),
                                "connect_client_to_server_sha256": (
                                    hashlib.sha256(tunnel_sent).hexdigest()
                                    if tunnel_frames
                                    else None
                                ),
                                "connect_server_to_client_sha256": (
                                    hashlib.sha256(tunnel_received).hexdigest()
                                    if tunnel_frames
                                    else None
                                ),
                                "connect_tunnel_verified": (
                                    fixture_verified if tunnel_frames else None
                                ),
                                "connect_transcript": _connect_transcript_evidence(
                                    runtime_tunnel_frames
                                ),
                                "connect_half_close_events": applied_half_close_events,
                                "connect_half_close_verified": len(
                                    applied_half_close_events
                                )
                                == len(tunnel_half_close_events),
                                "fixture_verified": fixture_verified,
                                "comparison_errors": comparison_errors,
                            }
                        )
                    )
                    if not fixture_verified:
                        connection_record["status"] = "failed"
                        connection_record["fixture_verified"] = False
                        break
                    processed += 1
                    connection_record.update(
                        {
                            "status": "closed",
                            "fixture_verified": True,
                            "sent_bytes": len(request_wire) + len(tunnel_sent),
                            "received_bytes": (
                                sum(
                                    int(item.get("wire_length") or 0)
                                    for item in actual_responses
                                )
                                + len(tunnel_received)
                            ),
                            "tunnel_sent_bytes": len(tunnel_sent),
                            "tunnel_received_bytes": len(tunnel_received),
                            "half_close_events": applied_half_close_events,
                            "cleanup": {
                                "socket_closed": True,
                                "mode": "finally_close",
                            },
                        }
                    )
                except (OSError, RuntimeError, ValueError) as exc:
                    message = str(exc) or exc.__class__.__name__
                    if connection_record.get("status") == "active":
                        connection_record["status"] = "failed"
                    connection_record["error"] = message
                    errors.append(message)
                    fail_closed_errors.append(message)
                    break
                finally:
                    _close_socket(replay_socket)
                    try:
                        socket_closed = replay_socket is None or replay_socket.fileno() == -1
                    except OSError:
                        socket_closed = True
                    connection_record["cleanup"] = {
                        "socket_closed": socket_closed,
                        "mode": "finally_close_verified",
                    }

        errors.extend(fail_closed_errors)
        source_count = len(transactions)
        all_verified = (
            source_count > 0
            and processed == source_count
            and all(bool(item.get("fixture_verified")) for item in replay_records)
        )
        if limit_reached:
            fail_closed_errors.append(
                f"HTTP fixture replay exhausted {limit_reached} before exact verification"
            )
            errors.extend(fail_closed_errors)
        if fail_closed_errors:
            status = "failed"
        elif errors:
            status = "failed"
        elif limitations or not all_verified:
            status = "partial"
            if not errors and not all_verified:
                errors.append("HTTP fixture replay did not verify every source transaction")
        else:
            status = "ok"

        after = {
            "session_state": "closed",
            "side_effects": transmit_attempted,
            "network_transmit": transmit_attempted,
            "transmit_attempted": transmit_attempted,
            "transport": "tcp",
            "application_protocol": "http/1.1",
            "capture_artifact": source_snapshot,
            "destination_endpoint": dict(destination),
            "destination_endpoint_identity": _endpoint_identity(destination),
            "target_endpoint": dict(destination),
            "allow_remote": False,
            "tls": _tls_audit_config(tls),
            "traffic_visibility": _tls_traffic_visibility(tls),
            "network_boundary": "explicit_loopback_ip_only",
            "replay_mode": "http_fixture",
            "replay_target_mode": "loopback",
            "connect_replay_scope": "bounded_loopback_opaque_tunnel",
            "http_fixture": _public_http_fixture(fixture),
            "fixture_verified": all_verified and not fail_closed_errors,
            "exact_fixture_replay_verified": all_verified and not fail_closed_errors,
            "generalized_replay": "complete" if not limitations else "partial",
            "generalized_replay_limitations": _deduplicate(limitations),
            "source_transaction_count": source_count,
            "processed_source_transaction_count": processed,
            "connection_count": len(connections),
            "connections": connections,
            "frame_count": len(runtime_frames),
            "frames": runtime_frames,
            "message_count": len(runtime_messages),
            "messages": runtime_messages,
            "request_response_pair_count": len(replay_records),
            "request_response_pairs": replay_records,
            "sent_bytes": sent_bytes,
            "received_bytes": received_bytes,
            "limit_reached": limit_reached,
            "real_socket_evidence": bool(connections)
            and all(
                _socket_identity_is_real_loopback(
                    _mapping(_mapping(item).get("socket_identity"))
                )
                for item in connections
            ),
            "outcome_class": status,
            "elapsed_ms": round((time.monotonic() - started) * 1_000, 3),
            "errors": _deduplicate(errors),
        }
        return {
            "status": status,
            "after_snapshot": _prune(after),
            "errors": _deduplicate(errors),
        }

    def _execute_udp_replay(self, plan: CapabilityPlan) -> dict[str, Any]:
        destination = _mapping(plan.parameters["destination_endpoint"])
        limits = _mapping(plan.parameters["limits"])
        allow_remote = plan.parameters.get("allow_remote") is True
        started = time.monotonic()
        deadline = started + int(limits["duration_ms"]) / 1_000.0
        frames: list[dict[str, Any]] = []
        connections: list[dict[str, Any]] = []
        errors: list[str] = []
        sent_bytes = 0
        received_bytes = 0
        limit_reached: Optional[str] = None
        source_path = Path(str(plan.parameters["capture_artifact"]))
        source_snapshot = _file_snapshot(source_path)

        try:
            payload, digest = _load_json_artifact(source_path)
            if digest != plan.parameters.get("capture_artifact_sha256"):
                raise RuntimeError("capture artifact changed before UDP replay execution")
            selected = _select_replay_frames(
                payload,
                str(plan.parameters["frame_direction"]),
                transport="udp",
                replay_mode="frames",
            )
            groups = _group_frames(selected)
            for connection_index, (source_connection_id, source_frames) in enumerate(
                groups.items(),
                start=1,
            ):
                if connection_index > int(limits["max_connections"]):
                    limit_reached = "max_connections"
                    break
                runtime_connection_id = f"udp-replay-{connection_index}"
                record = {
                    "connection_id": runtime_connection_id,
                    "source_connection_id": source_connection_id,
                    "destination": dict(destination),
                    "status": "active",
                }
                connections.append(record)
                replay_socket: Optional[socket.socket] = None
                echo_checks: list[bool] = []
                connection_sent = 0
                connection_received = 0
                try:
                    replay_socket = _connect_udp_loopback(
                        destination,
                        deadline=deadline,
                        timeout_ms=int(limits["socket_timeout_ms"]),
                        allow_remote=allow_remote,
                    )
                    for source_frame in source_frames:
                        data = _frame_payload(source_frame)
                        if len(frames) >= int(limits["max_frames"]):
                            limit_reached = "max_frames"
                            break
                        if sent_bytes + received_bytes + len(data) > int(limits["max_bytes"]):
                            limit_reached = "max_bytes"
                            break
                        _send_udp_connected(
                            replay_socket,
                            data,
                            deadline=deadline,
                            timeout_ms=int(limits["socket_timeout_ms"]),
                        )
                        sent_bytes += len(data)
                        connection_sent += len(data)
                        frames.append(
                            _runtime_frame(
                                sequence=len(frames) + 1,
                                connection_id=runtime_connection_id,
                                direction="client_to_server",
                                observed=data,
                                forwarded=data,
                                started=started,
                                transport="udp",
                                source_sequence=source_frame.get("sequence"),
                            )
                        )
                        if len(frames) >= int(limits["max_frames"]):
                            limit_reached = "max_frames"
                            break
                        remaining_bytes = int(limits["max_bytes"]) - sent_bytes - received_bytes
                        if remaining_bytes <= 0:
                            limit_reached = "max_bytes"
                            break
                        replay_socket.settimeout(
                            min(
                                int(limits["socket_timeout_ms"]) / 1_000.0,
                                max(0.001, deadline - time.monotonic()),
                            )
                        )
                        try:
                            response = replay_socket.recv(65_535)
                        except socket.timeout:
                            if bool(plan.parameters.get("verify_echo")):
                                raise RuntimeError("loopback UDP replay echo timed out")
                            continue
                        if len(response) > remaining_bytes:
                            limit_reached = "max_bytes"
                            break
                        received_bytes += len(response)
                        connection_received += len(response)
                        echo_checks.append(response == data)
                        frames.append(
                            _runtime_frame(
                                sequence=len(frames) + 1,
                                connection_id=runtime_connection_id,
                                direction="server_to_client",
                                observed=response,
                                forwarded=response,
                                started=started,
                                transport="udp",
                            )
                        )
                        if bool(plan.parameters.get("verify_echo")) and response != data:
                            raise RuntimeError(
                                "loopback UDP replay response did not equal sent datagram bytes"
                            )
                    record.update(
                        {
                            "status": "closed",
                            "sent_bytes": connection_sent,
                            "received_bytes": connection_received,
                            "echo_verified": (
                                bool(echo_checks) and all(echo_checks)
                                if bool(plan.parameters.get("verify_echo"))
                                else None
                            ),
                        }
                    )
                except (OSError, RuntimeError) as exc:
                    record["status"] = "failed"
                    record["error"] = str(exc) or exc.__class__.__name__
                    errors.append(str(record["error"]))
                finally:
                    _close_socket(replay_socket)
                if limit_reached:
                    break
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(str(exc) or exc.__class__.__name__)

        if errors and sent_bytes:
            status = "partial"
        elif errors:
            status = "failed"
        elif limit_reached and sent_bytes:
            status = "partial"
        elif not sent_bytes:
            status = "failed"
            errors.append("no UDP protocol frame bytes were replayed")
        else:
            status = "ok"
        after = {
            "session_state": "closed",
            "side_effects": sent_bytes > 0,
            "transport": "udp",
            "capture_artifact": source_snapshot,
            "destination_endpoint": dict(destination),
            "target_endpoint": dict(destination),
            "allow_remote": allow_remote,
            "tls": _tls_audit_config(plan.parameters.get("tls")),
            "network_boundary": _network_boundary(plan.parameters),
            "replay_mode": "frames",
            "timing_scale": float(plan.parameters.get("timing_scale") or 0.0),
            "connection_count": len(connections),
            "connections": connections,
            "frame_count": len(frames),
            "frames": frames,
            "sent_bytes": sent_bytes,
            "received_bytes": received_bytes,
            "limit_reached": limit_reached,
            "elapsed_ms": round((time.monotonic() - started) * 1_000, 3),
            "errors": _deduplicate(errors),
        }
        return {"status": status, "after_snapshot": _prune(after), "errors": errors}

    def _execution_result(
        self,
        plan: CapabilityPlan,
        *,
        validation: CapabilityValidation,
        status: str,
        before_snapshot: Mapping[str, Any],
        after_snapshot: Mapping[str, Any],
        errors: Sequence[str],
    ) -> CapabilityExecutionResult:
        network_boundary = _network_boundary(plan.parameters)
        tls_audit = _tls_audit_config(plan.parameters.get("tls"))
        traffic_visibility = _tls_traffic_visibility(plan.parameters.get("tls"))
        target_endpoint = _target_endpoint(plan.parameters)
        execution_mode = (
            str(after_snapshot.get("capture_mode") or "")
            or str(after_snapshot.get("replay_target_mode") or "")
            or _execution_kind(plan.action, plan.parameters)
        )
        before = dict(before_snapshot)
        before.setdefault("session_state", "planned")
        before.setdefault(
            "session",
            _session_snapshot(
                plan.session_id,
                action=plan.action,
                mode=execution_mode,
                state="planned",
            ),
        )
        after = dict(after_snapshot)
        after.setdefault("session_state", "closed")
        after.setdefault(
            "session",
            _session_snapshot(
                plan.session_id,
                action=plan.action,
                mode=execution_mode,
                state="closed",
            ),
        )
        rollback_plan = {
            **dict(plan.rollback_plan or {}),
            "completed": True,
            "session_state": "closed",
            "remote_state_restoration_supported": False,
        }
        artifact = _audit_artifact(plan.session_id, plan.action, status)
        artifact.metadata.update(
            {
                "target_identity": _target_identity(plan.target),
                "precondition_hash": plan.precondition_hash,
            }
        )
        manifest_entries = [
            _manifest_entry(
                artifact,
                status=status,
                session_id=plan.session_id,
                action=plan.action,
            )
        ]
        if plan.action in _REPLAY_ACTIONS:
            source_snapshot = _file_snapshot(plan.parameters.get("capture_artifact"))
            if source_snapshot.get("is_file"):
                manifest_entries.append(
                    _prune(
                        {
                            "schema_version": _SCHEMA_VERSION,
                            "path": source_snapshot.get("path"),
                            "kind": "protocol-runtime-capture-input",
                            "tool": self.capability_name,
                            "provider": self.provider_name,
                            "status": "ok",
                            "role": "replay-source",
                            "session_id": plan.session_id,
                            "sha256": source_snapshot.get("sha256"),
                            "size": source_snapshot.get("size"),
                        }
                    )
                )
            fixture = _mapping(plan.parameters.get("offline_fixture"))
            if fixture.get("kind") == "file" and fixture.get("path"):
                manifest_entries.append(
                    _prune(
                        {
                            "schema_version": _SCHEMA_VERSION,
                            "path": fixture.get("path"),
                            "kind": "protocol-runtime-offline-fixture",
                            "tool": self.capability_name,
                            "provider": self.provider_name,
                            "status": "ok",
                            "role": "offline-fixture",
                            "session_id": plan.session_id,
                            "sha256": fixture.get("sha256"),
                            "size": fixture.get("size"),
                            "external": True,
                            "materialized": False,
                        }
                    )
                )
            http_fixture = _mapping(plan.parameters.get("http_fixture"))
            if (
                plan.action == _HTTP_REPLAY
                and http_fixture.get("kind") == "file"
                and http_fixture.get("path")
            ):
                manifest_entries.append(
                    _prune(
                        {
                            "schema_version": _SCHEMA_VERSION,
                            "path": http_fixture.get("path"),
                            "kind": "protocol-runtime-http-fixture",
                            "tool": self.capability_name,
                            "provider": self.provider_name,
                            "status": "ok",
                            "role": "controlled-http-fixture",
                            "session_id": plan.session_id,
                            "sha256": http_fixture.get("sha256"),
                            "size": http_fixture.get("size"),
                            "external": True,
                            "materialized": False,
                        }
                    )
                )
        elif plan.action in _PASSIVE_ACTIONS:
            source_snapshot = _mapping(after.get("capture_source")) or _mapping(
                before.get("capture_source")
            )
            if source_snapshot.get("path"):
                adapter_source = plan.parameters.get("capture_mode") == "adapter"
                manifest_entries.append(
                    _prune(
                        {
                            "schema_version": _SCHEMA_VERSION,
                            "path": source_snapshot.get("path"),
                            "kind": "protocol-passive-capture-input",
                            "tool": self.capability_name,
                            "provider": self.provider_name,
                            "status": (
                                "ok" if source_snapshot.get("is_file") else status
                            ),
                            "role": (
                                "ephemeral-capture-source"
                                if adapter_source
                                else "passive-capture-source"
                            ),
                            "session_id": plan.session_id,
                            "sha256": source_snapshot.get("sha256"),
                            "bounded_sha256": source_snapshot.get("bounded_sha256"),
                            "fingerprint": source_snapshot.get("fingerprint"),
                            "size": source_snapshot.get("size"),
                            "bytes_hashed": source_snapshot.get("bytes_hashed"),
                            "truncated": source_snapshot.get("truncated"),
                            "external": not adapter_source,
                            "ephemeral": adapter_source,
                            "embedded_in": artifact.path,
                            "materialized": False,
                        }
                    )
                )
        actual_network_transmit = bool(
            after.get("network_transmit")
            or int(after.get("sent_bytes") or 0) > 0
            or int(after.get("forwarded_bytes") or 0) > 0
        )
        capture_source = _mapping(after.get("capture_source")) or _mapping(
            before.get("capture_source")
        )
        provenance = {
            **dict(plan.provenance or {}),
            "precondition_hash": plan.precondition_hash,
            "network_boundary": network_boundary,
            "allow_remote": plan.parameters.get("allow_remote") is True,
            "remote_access_opt_in": plan.parameters.get("allow_remote") is True,
            "target_endpoint": target_endpoint,
            "tls": tls_audit,
            "tls_enabled": bool(tls_audit.get("enabled")),
            "tls_verify": bool(tls_audit.get("verify")),
            "traffic_visibility": dict(
                _mapping(after.get("traffic_visibility")) or traffic_visibility
            ),
            "bounded_execution": True,
            "network_transmit": actual_network_transmit,
            "network_transmit_scope": (
                "none" if not actual_network_transmit else network_boundary
            ),
            "execution_mode": execution_mode,
            "real_provider": after.get("real_provider") is not False,
            "mock_provider": after.get("mock_provider") is True,
            "real_capture_success": bool(after.get("real_capture_success")),
            "outcome_class": after.get("outcome_class") or status,
            "dependency_state": after.get("dependency_state"),
            "capture_source_fingerprint": capture_source.get("fingerprint"),
            "capture_source_sha256": capture_source.get("sha256"),
            "capture_source_bounded_sha256": capture_source.get("bounded_sha256"),
            "session": dict(_mapping(after.get("session"))),
            "frame_count": int(after.get("frame_count") or 0),
            "message_count": int(after.get("message_count") or 0),
            "connect_tunnel_count": int(after.get("connect_tunnel_count") or 0),
            "flow_count": int(after.get("flow_count") or 0),
            "application_protocol": after.get("application_protocol")
            or plan.parameters.get("application_protocol"),
            "real_socket_evidence": bool(after.get("real_socket_evidence")),
            "fixture_verified": bool(after.get("fixture_verified")),
        }
        report_section = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "capability": self.capability_name,
            "provider": self.provider_name,
            "action": plan.action,
            "session_id": plan.session_id,
            "target_identity": _target_identity(plan.target),
            "precondition_hash": plan.precondition_hash,
            "session": dict(_mapping(after.get("session"))),
            "parameters": _public_parameters(plan.parameters),
            "before_snapshot": before,
            "after_snapshot": after,
            "rollback_plan": rollback_plan,
            "provenance": provenance,
            "validation": validation.to_dict(),
            "frame_summary": {
                "transport": after.get("transport")
                or plan.parameters.get("transport"),
                "frame_count": int(after.get("frame_count") or 0),
                "connection_count": int(after.get("connection_count") or 0),
                "observed_bytes": after.get("observed_bytes"),
                "forwarded_bytes": after.get("forwarded_bytes"),
                "sent_bytes": after.get("sent_bytes"),
                "received_bytes": after.get("received_bytes"),
            },
            "capture_summary": {
                "capture_mode": after.get("capture_mode"),
                "flow_count": int(after.get("flow_count") or 0),
                "message_count": int(after.get("message_count") or 0),
                "request_response_pair_count": int(
                    after.get("request_response_pair_count") or 0
                ),
                "connect_tunnel_count": int(after.get("connect_tunnel_count") or 0),
                "dependency_state": after.get("dependency_state"),
                "real_capture_success": bool(after.get("real_capture_success")),
                "outcome_class": after.get("outcome_class") or status,
                "budget": dict(_mapping(after.get("budget"))),
                "integrity": dict(_mapping(after.get("integrity"))),
            },
            "http_summary": {
                "application_protocol": after.get("application_protocol"),
                "capture_kind": after.get("capture_kind"),
                "message_count": int(after.get("message_count") or 0),
                "request_response_pair_count": int(
                    after.get("request_response_pair_count") or 0
                ),
                "connect_tunnel_count": int(after.get("connect_tunnel_count") or 0),
                "framing": dict(_mapping(after.get("http_framing"))),
                "integrity": dict(_mapping(after.get("integrity"))),
                "real_socket_evidence": bool(after.get("real_socket_evidence")),
                "fixture_verified": bool(after.get("fixture_verified")),
                "generalized_replay": after.get("generalized_replay"),
                "generalized_replay_limitations": list(
                    after.get("generalized_replay_limitations") or []
                ),
            },
            "tls_summary": {
                "configuration": tls_audit,
                "traffic_visibility": dict(
                    _mapping(after.get("traffic_visibility")) or traffic_visibility
                ),
                "connection_count": sum(
                    1
                    for item in after.get("connections", []) or []
                    if _mapping(_mapping(item).get("tls")).get("enabled")
                ),
            },
            "artifacts": [artifact.to_dict()],
            "evidence_manifest_entries": [dict(item) for item in manifest_entries],
            "errors": list(errors),
            "warnings": list(after.get("warnings") or []),
        }
        return CapabilityExecutionResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=before,
            after_snapshot=after,
            rollback_plan=rollback_plan,
            artifacts=[artifact],
            evidence_manifest_entries=manifest_entries,
            report_section=report_section,
            dashboard_trace=[
                {
                    "kind": "protocol_runtime_execution",
                    "capability": self.capability_name,
                    "provider": self.provider_name,
                    "action": plan.action,
                    "session_id": plan.session_id,
                    "status": status,
                    "frame_count": int(after.get("frame_count") or 0),
                    "connection_count": int(after.get("connection_count") or 0),
                    "flow_count": int(after.get("flow_count") or 0),
                    "message_count": int(after.get("message_count") or 0),
                    "request_response_pair_count": int(
                        after.get("request_response_pair_count") or 0
                    ),
                    "transport": after.get("transport")
                    or plan.parameters.get("transport"),
                    "network_boundary": network_boundary,
                    "network_transmit": actual_network_transmit,
                    "allow_remote": plan.parameters.get("allow_remote") is True,
                    "target_endpoint": target_endpoint,
                    "tls_enabled": bool(tls_audit.get("enabled")),
                    "tls_verify": bool(tls_audit.get("verify")),
                    "traffic_visibility": dict(
                        _mapping(after.get("traffic_visibility")) or traffic_visibility
                    ),
                    "dependency_state": after.get("dependency_state"),
                    "real_capture_success": bool(after.get("real_capture_success")),
                    "outcome_class": after.get("outcome_class") or status,
                    "application_protocol": after.get("application_protocol")
                    or plan.parameters.get("application_protocol"),
                    "real_socket_evidence": bool(
                        after.get("real_socket_evidence")
                    ),
                    "fixture_verified": bool(after.get("fixture_verified")),
                }
            ],
            provenance=provenance,
        )


class ProtocolRuntimeMockProvider(MockCapabilityProvider):
    def __init__(self) -> None:
        super().__init__(
            capability_name="protocol_runtime",
            provider_name="mock_protocol_runtime",
            priority=100,
        )


def _normalize_action(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")
    return _ACTION_ALIASES.get(normalized, normalized)


def _normalize_parameters(
    request: CapabilityRequest,
    *,
    action: str,
    context: Optional[dict[str, Any]],
) -> dict[str, Any]:
    params = dict(request.params or {})
    allow_remote = _bool_value(params.get("allow_remote"), False)
    limits = {
        "duration_ms": _duration_ms(params),
        "socket_timeout_ms": _int_value(
            params.get("socket_timeout_ms"),
            _DEFAULT_SOCKET_TIMEOUT_MS,
        ),
        "max_bytes": _int_value(params.get("max_bytes"), _DEFAULT_MAX_BYTES),
        "max_frames": _int_value(params.get("max_frames"), _DEFAULT_MAX_FRAMES),
        "max_connections": _int_value(
            params.get("max_connections"),
            _DEFAULT_MAX_CONNECTIONS,
        ),
        "max_packets": _int_value(params.get("max_packets"), _DEFAULT_MAX_PACKETS),
        "max_messages": _int_value(params.get("max_messages"), _DEFAULT_MAX_MESSAGES),
        "max_message_bytes": _int_value(
            params.get("max_message_bytes"),
            _DEFAULT_MAX_MESSAGE_BYTES,
        ),
        "max_stream_bytes": _int_value(
            params.get("max_stream_bytes"),
            _DEFAULT_MAX_STREAM_BYTES,
        ),
        "max_correlation_messages": _int_value(
            params.get("max_correlation_messages"),
            _DEFAULT_MAX_CORRELATION_MESSAGES,
        ),
        "max_request_response_pairs": _int_value(
            params.get("max_request_response_pairs"),
            _DEFAULT_MAX_REQUEST_RESPONSE_PAIRS,
        ),
        "max_http_header_bytes": _int_value(
            params.get("max_http_header_bytes", params.get("max_header_bytes")),
            _DEFAULT_MAX_HTTP_HEADER_BYTES,
        ),
        "max_http_headers": _int_value(
            params.get("max_http_headers", params.get("max_headers")),
            _DEFAULT_MAX_HTTP_HEADERS,
        ),
    }
    if action in _PASSIVE_ACTIONS:
        source_value = (
            params.get("capture_source")
            or params.get("capture_path")
            or params.get("source_path")
            or params.get("path")
            or params.get("capture_artifact")
            or request.target.path
            or ""
        )
        source_path = (
            str(Path(str(source_value)).expanduser().resolve()) if source_value else ""
        )
        requested_mode = str(params.get("capture_mode") or "").strip().lower().replace("-", "_")
        capture_mode = (
            "offline_import"
            if action == _PASSIVE_IMPORT or source_path or requested_mode in {"import", "offline", "file"}
            else "adapter"
        )
        if requested_mode in {"adapter", "live", "passive_live"}:
            capture_mode = "adapter"
        adapter = str(params.get("capture_adapter") or params.get("adapter") or "auto").strip().lower()
        interface = str(
            params.get("capture_interface")
            or params.get("interface")
            or _default_loopback_capture_interface()
        ).strip()
        return {
            "capture_mode": capture_mode,
            "capture_source": source_path,
            "source_format": _normalize_capture_format(
                params.get("source_format")
                or params.get("input_format")
                or params.get("format")
            ),
            "capture_adapter": adapter,
            "capture_interface": interface,
            "limits": limits,
            "transport": "mixed",
            "allow_remote": False,
            "network_boundary": (
                "offline_evidence_only"
                if capture_mode == "offline_import"
                else "passive_loopback_interface_only"
            ),
            "source_hint": (
                str(context.get("source_hint"))
                if isinstance(context, Mapping) and context.get("source_hint")
                else None
            ),
        }

    transport = "udp" if action in {_UDP_CAPTURE, _UDP_REPLAY} else "tcp"
    application_protocol = _normalize_application_protocol(
        params.get("application_protocol")
        or params.get("protocol")
        or params.get("protocol_version"),
        http_default=action in {_HTTP_CAPTURE, _HTTP_REPLAY},
    )
    if action in _CAPTURE_ACTIONS:
        listen_endpoint = {
            "host": str(params.get("listen_host") or ""),
            "port": _int_value(params.get("listen_port"), -1),
        }
        upstream_endpoint = {
            "host": str(params.get("upstream_host") or ""),
            "port": _int_value(params.get("upstream_port"), -1),
        }
        return {
            "listen_endpoint": listen_endpoint,
            "upstream_endpoint": upstream_endpoint,
            "limits": limits,
            "mutation": _mapping(params.get("mutation")),
            "transport": transport,
            "application_protocol": application_protocol,
            "allow_remote": allow_remote,
            "tls": _normalize_tls_parameters(
                params,
                endpoint_host=str(upstream_endpoint["host"]),
            ),
            "network_boundary": (
                "explicit_ip_remote_opt_in"
                if allow_remote
                else "explicit_loopback_ip_only"
            ),
        }

    source_value = (
        params.get("capture_artifact")
        or params.get("artifact_path")
        or request.target.path
        or ""
    )
    source_path = str(Path(str(source_value)).expanduser().resolve()) if source_value else ""
    offline_fixture = _normalize_offline_fixture(params.get("offline_fixture"))
    requested_target_mode = str(
        params.get("replay_target_mode") or params.get("destination_mode") or ""
    ).strip().lower().replace("-", "_")
    replay_target_mode = (
        "offline_fixture"
        if offline_fixture.get("enabled")
        or requested_target_mode in {"offline", "fixture", "offline_fixture"}
        else "loopback"
    )
    if action == _HTTP_REPLAY:
        replay_target_mode = "loopback"
    if replay_target_mode == "offline_fixture" and not offline_fixture:
        offline_fixture = {"enabled": True, "kind": "explicit"}
    if replay_target_mode == "offline_fixture":
        destination_endpoint = {"host": "", "port": -1}
        requested_transport = str(params.get("transport") or transport).strip().lower()
        transport = requested_transport if requested_transport in {"tcp", "udp", "raw"} else requested_transport
    else:
        destination_endpoint = {
            "host": str(params.get("destination_host") or params.get("host") or ""),
            "port": _int_value(
                params.get("destination_port", params.get("port")),
                -1,
            ),
        }
    requested_direction = str(params.get("frame_direction") or "client_to_server").lower()
    replay_mode_value = str(params.get("replay_mode") or "").strip().lower()
    session_replay = _bool_value(params.get("session_replay"), False)
    if requested_direction in _SESSION_DIRECTIONS or session_replay:
        replay_mode = "session"
        frame_direction = "session"
    else:
        replay_mode = replay_mode_value or "frames"
        frame_direction = requested_direction
    return {
        "capture_artifact": source_path,
        "destination_endpoint": destination_endpoint,
        "replay_target_mode": replay_target_mode,
        "offline_fixture": offline_fixture,
        "frame_direction": "session" if action == _HTTP_REPLAY else frame_direction,
        "replay_mode": "session" if action == _HTTP_REPLAY else replay_mode,
        "timing_scale": _float_value(params.get("timing_scale"), 0.0),
        "verify_echo": _bool_value(params.get("verify_echo"), False),
        "transport": transport,
        "application_protocol": application_protocol,
        "limits": limits,
        "allow_remote": allow_remote,
        "tls": _normalize_tls_parameters(
            params,
            endpoint_host=str(destination_endpoint["host"]),
        ),
        "http_fixture": _normalize_http_fixture(
            params.get("http_fixture")
            or params.get("controlled_fixture")
            or params.get("fixture")
        ),
        "network_boundary": (
            "offline_fixture_only"
            if replay_target_mode == "offline_fixture"
            else "explicit_loopback_ip_only"
        ),
        "source_hint": (
            str(context.get("source_hint"))
            if isinstance(context, Mapping) and context.get("source_hint")
            else None
        ),
    }


def _duration_ms(params: Mapping[str, Any]) -> int:
    if params.get("duration_ms") not in (None, ""):
        return _int_value(params.get("duration_ms"), -1)
    if params.get("duration") not in (None, ""):
        try:
            return int(float(params["duration"]) * 1_000)
        except (TypeError, ValueError, OverflowError):
            return -1
    return _DEFAULT_DURATION_MS


def _int_value(value: Any, default: int) -> int:
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return -1


def _float_value(value: Any, default: float) -> float:
    if value in (None, ""):
        return default
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return -1.0
    if result != result or result in (float("inf"), float("-inf")):
        return -1.0
    return result


def _bool_value(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_application_protocol(value: Any, *, http_default: bool) -> str:
    normalized = str(value or "").strip().lower().replace("_", "").replace("-", "")
    if normalized in {"http", "http1", "http11", "http/1.1"}:
        return "http/1.1"
    if not normalized and http_default:
        return "http/1.1"
    return "opaque"


def _normalize_tls_parameters(
    params: Mapping[str, Any],
    *,
    endpoint_host: str,
) -> dict[str, Any]:
    tls_value = params.get("tls")
    nested = _mapping(tls_value)
    if "tls_enabled" in params:
        enabled_value = params.get("tls_enabled")
    elif "enabled" in nested:
        enabled_value = nested.get("enabled")
    elif isinstance(tls_value, Mapping):
        enabled_value = True
    else:
        enabled_value = tls_value
    enabled = _bool_value(enabled_value, False)

    verify_value = nested.get(
        "verify",
        params.get("tls_verify", params.get("verify_tls", True)),
    )
    server_hostname_value = nested.get(
        "server_hostname",
        params.get("tls_server_hostname", params.get("server_hostname")),
    )
    ca_file_value = nested.get(
        "ca_file",
        nested.get(
            "cafile",
            params.get("tls_ca_file", params.get("ca_file", params.get("cafile"))),
        ),
    )
    ca_file = (
        str(Path(str(ca_file_value)).expanduser().resolve())
        if ca_file_value not in (None, "")
        else ""
    )
    ca_snapshot = _file_snapshot(ca_file) if ca_file else {}
    server_hostname = str(server_hostname_value or (endpoint_host if enabled else ""))
    return {
        "enabled": enabled,
        "mode": "client",
        "verify": _bool_value(verify_value, True),
        "server_hostname": server_hostname,
        "ca_file": ca_file,
        "ca_file_sha256": ca_snapshot.get("sha256"),
        "ca_file_size": ca_snapshot.get("size"),
        "minimum_version": "TLSv1_2",
    }


def _normalize_capture_format(value: Any) -> Optional[str]:
    text = str(value or "").strip().lower().replace("-", "").replace("_", "")
    aliases = {
        "": None,
        "auto": None,
        "pcap": "pcap",
        "cap": "pcap",
        "pcapng": "pcapng",
        "json": "json",
        "jsonl": "jsonl",
        "ndjson": "jsonl",
        "jsonlines": "jsonl",
        "raw": "raw",
        "bytes": "raw",
        "binary": "raw",
    }
    return aliases.get(text, str(value or "").strip().lower())


def _default_loopback_capture_interface() -> str:
    if os.name == "nt":
        return r"\Device\NPF_Loopback"
    if sys.platform == "darwin":
        return "lo0"
    return "lo"


def _validate_loopback_capture_interface(value: Any) -> tuple[bool, str]:
    interface = str(value or "").strip()
    if not interface:
        return False, "an explicit loopback capture interface is required"
    normalized = interface.lower().replace(" ", "")
    accepted = (
        normalized in {"lo", "lo0", "loopback", r"\device\npf_loopback"}
        or "loopback" in normalized
    )
    if not accepted:
        return False, "passive capture is restricted to a loopback interface"
    if any(character in interface for character in ("\x00", "\r", "\n")):
        return False, "capture interface contains invalid control characters"
    return True, ""


def _normalize_offline_fixture(value: Any) -> dict[str, Any]:
    if value in (None, "", False):
        return {}
    if value is True:
        return {"enabled": True, "kind": "explicit"}
    if isinstance(value, (str, os.PathLike)):
        snapshot = _file_snapshot(value)
        return _prune(
            {
                "enabled": True,
                "kind": "file",
                "path": snapshot.get("path"),
                "sha256": snapshot.get("sha256"),
                "size": snapshot.get("size"),
                "exists": snapshot.get("exists"),
                "is_file": snapshot.get("is_file"),
                "error": snapshot.get("error"),
            }
        )
    if isinstance(value, Mapping):
        fixture = dict(value)
        fixture["enabled"] = _bool_value(fixture.get("enabled"), True)
        if fixture.get("path"):
            snapshot = _file_snapshot(fixture["path"])
            fixture.update(
                {
                    "kind": "file",
                    "path": snapshot.get("path"),
                    "sha256": snapshot.get("sha256"),
                    "size": snapshot.get("size"),
                    "exists": snapshot.get("exists"),
                    "is_file": snapshot.get("is_file"),
                    "error": snapshot.get("error"),
                }
            )
        else:
            fixture.setdefault("kind", "explicit")
        return _prune(fixture)
    return {"enabled": True, "kind": "invalid", "value_type": type(value).__name__}


def _normalize_http_fixture(value: Any) -> dict[str, Any]:
    if value in (None, "", True):
        return {
            "enabled": True,
            "kind": "capture_artifact",
            "match_mode": "exact",
        }
    if value is False:
        return {"enabled": False, "kind": "disabled", "match_mode": "exact"}
    if isinstance(value, (str, os.PathLike)):
        snapshot = _file_snapshot(value)
        return _prune(
            {
                "enabled": True,
                "kind": "file",
                "path": snapshot.get("path"),
                "sha256": snapshot.get("sha256"),
                "size": snapshot.get("size"),
                "exists": snapshot.get("exists"),
                "is_file": snapshot.get("is_file"),
                "error": snapshot.get("error"),
                "match_mode": "exact",
            }
        )
    if isinstance(value, Mapping):
        fixture = dict(value)
        fixture["enabled"] = _bool_value(fixture.get("enabled"), True)
        fixture["match_mode"] = str(fixture.get("match_mode") or "exact").lower()
        if fixture.get("path"):
            snapshot = _file_snapshot(fixture["path"])
            fixture.update(
                {
                    "kind": "file",
                    "path": snapshot.get("path"),
                    "sha256": snapshot.get("sha256"),
                    "size": snapshot.get("size"),
                    "exists": snapshot.get("exists"),
                    "is_file": snapshot.get("is_file"),
                    "error": snapshot.get("error"),
                }
            )
        else:
            fixture.setdefault("kind", "explicit")
        return _prune(fixture)
    return {
        "enabled": True,
        "kind": "invalid",
        "value_type": type(value).__name__,
        "match_mode": "exact",
    }


def _public_fixture(value: Any) -> dict[str, Any]:
    fixture = _mapping(value)
    return _prune(
        {
            "enabled": fixture.get("enabled"),
            "kind": fixture.get("kind"),
            "path": fixture.get("path"),
            "sha256": fixture.get("sha256"),
            "size": fixture.get("size"),
            "expected_frame_count": fixture.get("expected_frame_count"),
            "expected_payload_hashes_configured": bool(
                fixture.get("expected_payload_sha256")
            ),
            "expected_payloads_configured": bool(fixture.get("expected_payloads_base64")),
        }
    )


def _public_http_fixture(value: Any) -> dict[str, Any]:
    fixture = _mapping(value)
    return _prune(
        {
            "enabled": fixture.get("enabled"),
            "kind": fixture.get("kind"),
            "path": fixture.get("path"),
            "sha256": fixture.get("sha256"),
            "size": fixture.get("size"),
            "match_mode": fixture.get("match_mode"),
            "expected_transaction_count": fixture.get("expected_transaction_count"),
            "expected_status_codes": fixture.get("expected_status_codes"),
            "expected_request_wire_sha256": fixture.get(
                "expected_request_wire_sha256"
            ),
            "expected_request_header_sha256": fixture.get(
                "expected_request_header_sha256"
            ),
            "expected_request_body_sha256": fixture.get(
                "expected_request_body_sha256"
            ),
            "expected_response_wire_sha256": fixture.get(
                "expected_response_wire_sha256"
            ),
            "expected_response_header_sha256": fixture.get(
                "expected_response_header_sha256"
            ),
            "expected_response_body_sha256": fixture.get(
                "expected_response_body_sha256"
            ),
            "endpoint": fixture.get("endpoint"),
            "endpoint_identity_sha256": fixture.get("endpoint_identity_sha256"),
            "peer_certificate_sha256": fixture.get("peer_certificate_sha256"),
            "require_verified_tls": fixture.get("require_verified_tls"),
        }
    )


def _offline_fixture_errors(value: Any) -> list[str]:
    fixture = _mapping(value)
    errors: list[str] = []
    if fixture.get("enabled") is not True:
        return ["offline fixture replay requires an explicit offline_fixture"]
    kind = str(fixture.get("kind") or "")
    if kind == "invalid":
        errors.append("offline fixture must be a boolean, path, or mapping")
    if kind == "file":
        snapshot = _file_snapshot(fixture.get("path"))
        if not snapshot.get("is_file") or snapshot.get("error"):
            errors.append("offline fixture file is unavailable")
        if str(snapshot.get("sha256") or "") != str(fixture.get("sha256") or ""):
            errors.append("offline fixture changed after planning")
        if snapshot.get("size") != fixture.get("size"):
            errors.append("offline fixture size changed after planning")
    hashes = fixture.get("expected_payload_sha256")
    if hashes is not None:
        values = hashes if isinstance(hashes, list) else [hashes]
        if len(values) > _MAX_FRAMES or any(
            not re.fullmatch(r"[0-9a-fA-F]{64}", str(item or "")) for item in values
        ):
            errors.append("offline fixture expected_payload_sha256 is invalid")
    payloads = fixture.get("expected_payloads_base64")
    if payloads is not None:
        values = payloads if isinstance(payloads, list) else [payloads]
        if len(values) > _MAX_FRAMES:
            errors.append("offline fixture contains too many expected payloads")
        else:
            total = 0
            for item in values:
                try:
                    decoded = base64.b64decode(str(item).encode("ascii"), validate=True)
                except (ValueError, UnicodeEncodeError):
                    errors.append("offline fixture expected_payloads_base64 is invalid")
                    break
                total += len(decoded)
            if total > _MAX_BYTES:
                errors.append("offline fixture expected payloads exceed the byte budget")
    expected_count = fixture.get("expected_frame_count")
    if expected_count is not None and (
        not isinstance(expected_count, int)
        or isinstance(expected_count, bool)
        or not 0 <= expected_count <= _MAX_FRAMES
    ):
        errors.append("offline fixture expected_frame_count is invalid")
    return _deduplicate(errors)


def _verify_offline_fixture(value: Any, frames: Sequence[Mapping[str, Any]]) -> list[str]:
    fixture = _mapping(value)
    errors = _offline_fixture_errors(fixture)
    if errors:
        return errors
    payloads: list[bytes] = []
    for frame in frames:
        try:
            payloads.append(_frame_payload(frame))
        except ValueError as exc:
            errors.append(str(exc))
    expected_count = fixture.get("expected_frame_count")
    if expected_count is not None and int(expected_count) != len(payloads):
        errors.append("offline fixture frame count did not match selected replay frames")
    expected_hashes = fixture.get("expected_payload_sha256")
    if expected_hashes is not None:
        values = expected_hashes if isinstance(expected_hashes, list) else [expected_hashes]
        actual = [hashlib.sha256(item).hexdigest() for item in payloads]
        if [str(item).lower() for item in values] != actual:
            errors.append("offline fixture payload hashes did not match selected replay frames")
    expected_payloads = fixture.get("expected_payloads_base64")
    if expected_payloads is not None:
        values = expected_payloads if isinstance(expected_payloads, list) else [expected_payloads]
        decoded = [base64.b64decode(str(item).encode("ascii"), validate=True) for item in values]
        if decoded != payloads:
            errors.append("offline fixture payloads did not match selected replay frames")
    return _deduplicate(errors)


def _capture_source_snapshot(value: Any, *, max_bytes: int) -> dict[str, Any]:
    path = Path(str(value or "")).expanduser().resolve()
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "is_file": path.is_file(),
    }
    if not result["is_file"]:
        return result
    try:
        stat = path.stat()
        read_limit = max(1, min(int(max_bytes or 0), _MAX_BYTES))
        digest = hashlib.sha256()
        bytes_hashed = 0
        with path.open("rb") as handle:
            while bytes_hashed < read_limit:
                chunk = handle.read(min(1024 * 1024, read_limit - bytes_hashed))
                if not chunk:
                    break
                digest.update(chunk)
                bytes_hashed += len(chunk)
        truncated = stat.st_size > bytes_hashed
        result.update(
            {
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "bytes_hashed": bytes_hashed,
                "bounded_sha256": digest.hexdigest(),
                "truncated": truncated,
            }
        )
        if not truncated:
            result["sha256"] = digest.hexdigest()
        result["fingerprint"] = _sha256_json(
            {
                "path": str(path),
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "bytes_hashed": bytes_hashed,
                "bounded_sha256": digest.hexdigest(),
            }
        )
    except OSError as exc:
        result["error"] = str(exc)
    return result


def _capture_snapshot_identity(value: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        value.get("path"),
        value.get("size"),
        value.get("mtime_ns"),
        value.get("bytes_hashed"),
        value.get("bounded_sha256"),
        value.get("fingerprint"),
    )


def _executable_snapshot(value: Any) -> dict[str, Any]:
    path = Path(str(value or "")).expanduser().resolve()
    result = {"path": str(path), "is_file": path.is_file()}
    if not result["is_file"]:
        return result
    try:
        stat = path.stat()
        result.update({"size": stat.st_size, "mtime_ns": stat.st_mtime_ns})
    except OSError as exc:
        result["error"] = str(exc)
    return result


def _probe_passive_capture_adapter(requested: str) -> dict[str, Any]:
    adapter = str(requested or "auto").strip().lower()
    if adapter != "auto" and adapter not in _CAPTURE_ADAPTERS:
        return {
            "status": "dependency-gated",
            "requested": adapter,
            "real_adapter": False,
            "reason": "unsupported passive capture adapter",
        }
    candidates = _CAPTURE_ADAPTERS if adapter == "auto" else (adapter,)
    checked: list[str] = []
    for candidate in candidates:
        checked.append(candidate)
        executable = shutil.which(candidate)
        if not executable:
            continue
        snapshot = _executable_snapshot(executable)
        if not snapshot.get("is_file") or snapshot.get("error"):
            continue
        if os.name != "nt" and not os.access(str(snapshot["path"]), os.X_OK):
            continue
        return {
            "status": "available",
            "requested": adapter,
            "adapter": candidate,
            "executable": snapshot,
            "dependency_kind": "local_executable",
            "passive": True,
            "real_adapter": True,
            "mock_provider": False,
        }
    return {
        "status": "dependency-gated",
        "requested": adapter,
        "checked": checked,
        "dependency_kind": "local_executable",
        "passive": True,
        "real_adapter": False,
        "mock_provider": False,
        "reason": f"passive capture dependency unavailable: {', '.join(checked)}",
    }


def _adapter_probe_identity(value: Mapping[str, Any]) -> tuple[Any, ...]:
    executable = _mapping(value.get("executable"))
    return (
        value.get("status"),
        value.get("adapter"),
        executable.get("path"),
        executable.get("size"),
        executable.get("mtime_ns"),
    )


def _run_protocol_capture(path: Path, parameters: Mapping[str, Any]) -> dict[str, Any]:
    limits = _mapping(parameters.get("limits"))
    max_messages = min(
        int(limits.get("max_messages") or 0),
        int(limits.get("max_correlation_messages") or 0),
    )
    max_message_bytes = min(
        int(limits.get("max_message_bytes") or 0),
        int(limits.get("max_stream_bytes") or 0),
    )
    try:
        result = protocol_capture(
            path,
            source_format=_normalize_capture_format(parameters.get("source_format")),
            max_bytes=int(limits.get("max_bytes") or 0),
            max_packets=int(limits.get("max_packets") or 0),
            max_messages=max_messages,
            max_message_bytes=max_message_bytes,
        )
        return dict(result) if isinstance(result, Mapping) else {
            "status": "unavailable",
            "warnings": ["protocol capture parser returned a non-object result"],
        }
    except (OSError, TypeError, ValueError) as exc:
        return {
            "status": "unavailable",
            "warnings": [f"protocol capture import failed: {type(exc).__name__}: {exc}"],
            "flows": [],
            "messages": [],
            "request_response_pairs": [],
            "dependencies": {"pcap_parser": "builtin"},
        }


def _apply_capture_result_budgets(
    value: Mapping[str, Any],
    limits: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    result = dict(value)
    messages = [dict(item) for item in result.get("messages", []) if isinstance(item, Mapping)]
    pairs = [
        dict(item)
        for item in result.get("request_response_pairs", [])
        if isinstance(item, Mapping)
    ]
    warnings = [str(item) for item in result.get("warnings", []) if str(item)]
    generated_warnings: list[str] = []
    budget_events: list[str] = []
    pair_limit = int(limits.get("max_request_response_pairs") or 0)
    pair_total = len(pairs)
    if pair_total > pair_limit:
        pairs = pairs[:pair_limit]
        warning = f"request/response pairs truncated at max_request_response_pairs={pair_limit}"
        warnings.append(warning)
        generated_warnings.append(warning)
        budget_events.append("max_request_response_pairs")
    truncated_messages = sum(bool(item.get("payload_truncated")) for item in messages)
    gap_count = sum(
        int(_mapping(item.get("metadata")).get("reassembly_gap_count") or 0)
        for item in messages
    )
    overlap_bytes = sum(
        int(_mapping(item.get("metadata")).get("overlap_bytes") or 0)
        for item in messages
    )
    if gap_count:
        warning = f"TCP stream reassembly observed {gap_count} sequence gap(s)"
        warnings.append(warning)
        generated_warnings.append(warning)
    source = _mapping(result.get("source"))
    if source.get("limit_hit") or source.get("truncated") or truncated_messages:
        budget_events.append("capture_or_stream_budget")
    if gap_count:
        budget_events.append("reassembly_gap")
    if budget_events and result.get("status") == "ok":
        result["status"] = "partial"
    result.update(
        {
            "messages": messages,
            "request_response_pairs": pairs,
            "warnings": _deduplicate(warnings),
            "integrity": {
                "truncated_message_count": truncated_messages,
                "reassembly_gap_count": gap_count,
                "overlap_bytes": overlap_bytes,
                "damaged": bool(gap_count),
            },
            "budget": {
                "limits": dict(limits),
                "effective_max_messages": min(
                    int(limits.get("max_messages") or 0),
                    int(limits.get("max_correlation_messages") or 0),
                ),
                "effective_max_stream_bytes": min(
                    int(limits.get("max_message_bytes") or 0),
                    int(limits.get("max_stream_bytes") or 0),
                ),
                "request_response_pair_count_before_limit": pair_total,
                "request_response_pair_count": len(pairs),
                "limit_reached": _deduplicate(budget_events),
            },
        }
    )
    return result, _deduplicate(generated_warnings)


def _passive_capture_status(
    capture_result: Mapping[str, Any],
    errors: Sequence[str],
    *,
    target_drift: bool,
) -> str:
    messages = capture_result.get("messages")
    message_count = len(messages) if isinstance(messages, list) else 0
    if target_drift:
        return "failed"
    parser_status = str(capture_result.get("status") or "unavailable")
    if not message_count:
        return "unavailable"
    if errors:
        return "partial"
    if parser_status in {"ok", "partial"}:
        return parser_status
    return "partial"


def _passive_capture_after(
    plan: CapabilityPlan,
    *,
    status: str,
    source: Mapping[str, Any],
    capture_result: Mapping[str, Any],
    dependency_probe: Mapping[str, Any],
    elapsed_ms: float,
    errors: Sequence[str],
    adapter_execution: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    flows = [dict(item) for item in capture_result.get("flows", []) if isinstance(item, Mapping)]
    messages = [
        dict(item) for item in capture_result.get("messages", []) if isinstance(item, Mapping)
    ]
    pairs = [
        dict(item)
        for item in capture_result.get("request_response_pairs", [])
        if isinstance(item, Mapping)
    ]
    dependency_state = str(dependency_probe.get("status") or "unavailable")
    capture_mode = str(plan.parameters.get("capture_mode") or "offline_import")
    execution = _mapping(adapter_execution)
    real_execution = (
        capture_mode == "offline_import"
        or (
            execution.get("started") is True
            and execution.get("real_adapter") is True
            and execution.get("mock_provider") is not True
        )
    )
    real_success = (
        status in {"ok", "partial"}
        and bool(messages)
        and dependency_probe.get("real_adapter") is True
        and real_execution
    )
    return _prune(
        {
            "session_state": "closed",
            "session": _session_snapshot(
                plan.session_id,
                action=plan.action,
                mode=str(plan.parameters.get("capture_mode") or "offline_import"),
                state="closed",
            ),
            "side_effects": False,
            "network_transmit": False,
            "capture_mode": capture_mode,
            "capture_source": dict(source),
            "source": dict(_mapping(capture_result.get("source"))) or dict(source),
            "source_format": (
                _mapping(capture_result.get("source")).get("format")
                or plan.parameters.get("source_format")
            ),
            "capture_interface": plan.parameters.get("capture_interface"),
            "capture_adapter": dependency_probe.get("adapter"),
            "dependency_state": dependency_state,
            "dependency_probe": dict(dependency_probe),
            "dependencies": dict(_mapping(capture_result.get("dependencies"))),
            "adapter_execution": dict(adapter_execution or {}),
            "network_boundary": _network_boundary(plan.parameters),
            "limits": dict(_mapping(plan.parameters.get("limits"))),
            "budget": dict(_mapping(capture_result.get("budget"))),
            "integrity": dict(_mapping(capture_result.get("integrity"))),
            "flow_count": len(flows),
            "flows": flows,
            "message_count": len(messages),
            "messages": messages,
            "request_response_pair_count": len(pairs),
            "request_response_pairs": pairs,
            "field_stats": dict(_mapping(capture_result.get("field_stats"))),
            "field_statistics": dict(_mapping(capture_result.get("field_statistics"))),
            "frame_count": len(messages),
            "connection_count": len(flows),
            "observed_bytes": _mapping(capture_result.get("source")).get("bytes_read"),
            "limit_reached": _mapping(capture_result.get("budget")).get("limit_reached"),
            "truncated": bool(
                _mapping(capture_result.get("source")).get("truncated")
                or _mapping(capture_result.get("integrity")).get("truncated_message_count")
            ),
            "warnings": list(capture_result.get("warnings") or []),
            "errors": _deduplicate(errors),
            "real_provider": True,
            "mock_provider": False,
            "real_capture_success": real_success,
            "outcome_class": (
                "real"
                if real_success
                else "dependency-gated"
                if status == "dependency-gated"
                else "unavailable"
                if status == "unavailable" or not messages
                else "non-real"
            ),
            "elapsed_ms": round(float(elapsed_ms), 3),
        }
    )


def _capture_adapter_command(
    parameters: Mapping[str, Any],
    probe: Mapping[str, Any],
    destination: Path,
) -> tuple[list[str], dict[str, int]]:
    limits = _mapping(parameters.get("limits"))
    adapter = str(probe.get("adapter") or "")
    executable = str(_mapping(probe.get("executable")).get("path") or "")
    interface = str(parameters.get("capture_interface") or "")
    duration_ms = int(limits.get("duration_ms") or 0)
    max_bytes = int(limits.get("max_bytes") or 0)
    snaplen = max(
        64,
        min(
            65_535,
            max_bytes,
            int(limits.get("max_message_bytes") or _DEFAULT_MAX_MESSAGE_BYTES),
        ),
    )
    packet_budget = max(
        1,
        min(
            int(limits.get("max_packets") or 1),
            max_bytes // max(1, snaplen) + 1,
        ),
    )
    duration_seconds = max(0.001, duration_ms / 1_000.0)
    if adapter == "dumpcap":
        command = [
            executable,
            "-i",
            interface,
            "-q",
            "-s",
            str(snaplen),
            "-c",
            str(packet_budget),
            "-a",
            f"duration:{duration_seconds:g}",
            "-a",
            f"filesize:{max(1, (max_bytes + 1023) // 1024)}",
            "-w",
            str(destination),
        ]
    elif adapter == "tshark":
        command = [
            executable,
            "-i",
            interface,
            "-q",
            "-s",
            str(snaplen),
            "-c",
            str(packet_budget),
            "-a",
            f"duration:{duration_seconds:g}",
            "-w",
            str(destination),
        ]
    else:
        command = [
            executable,
            "-i",
            interface,
            "-nn",
            "-U",
            "-s",
            str(snaplen),
            "-c",
            str(packet_budget),
            "-w",
            str(destination),
        ]
    return command, {"snaplen": snaplen, "packet_budget": packet_budget}


def _run_passive_capture_adapter(
    parameters: Mapping[str, Any],
    probe: Mapping[str, Any],
) -> dict[str, Any]:
    limits = _mapping(parameters.get("limits"))
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="protocol-passive-") as temporary_dir:
        capture_path = Path(temporary_dir) / "capture.bin"
        command, command_limits = _capture_adapter_command(parameters, probe, capture_path)
        duration_seconds = int(limits.get("duration_ms") or 0) / 1_000.0
        timeout = duration_seconds + max(
            1.0,
            int(limits.get("socket_timeout_ms") or 0) / 1_000.0,
        )
        return_code: Optional[int] = None
        timed_out = False
        stderr = b""
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return_code = int(completed.returncode)
            stderr = bytes(completed.stderr or b"")[:8192]
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stderr = bytes(exc.stderr or b"")[:8192]
        except (OSError, ValueError) as exc:
            reason = f"passive capture adapter could not start: {exc}"
            return {
                "status": "dependency-gated",
                "capture_result": {},
                "source": {},
                "errors": [reason],
                "execution": {
                    "adapter": probe.get("adapter"),
                    "started": False,
                    "network_transmit": False,
                },
            }

        stderr_text = stderr.decode("utf-8", errors="replace").strip()
        permission_failure = any(
            token in stderr_text.lower()
            for token in ("permission", "not permitted", "access denied", "no interfaces")
        )
        if return_code not in (None, 0) and not capture_path.is_file():
            errors.append(stderr_text or f"capture adapter exited with status {return_code}")
        source = _capture_source_snapshot(
            capture_path,
            max_bytes=int(limits.get("max_bytes") or 0),
        )
        capture_result = (
            _run_protocol_capture(capture_path, parameters)
            if capture_path.is_file()
            else {
                "status": "unavailable",
                "flows": [],
                "messages": [],
                "request_response_pairs": [],
                "warnings": ["passive capture adapter produced no evidence file"],
                "dependencies": {"pcap_parser": "builtin"},
            }
        )
        return {
            "status": "dependency-gated" if permission_failure else "captured",
            "capture_result": capture_result,
            "source": source,
            "errors": errors,
            "execution": {
                "adapter": probe.get("adapter"),
                "started": True,
                "real_adapter": True,
                "mock_provider": False,
                "return_code": return_code,
                "timed_out": timed_out,
                "stderr": stderr_text[:2048],
                "network_transmit": False,
                "evidence_file_created": capture_path.is_file(),
                "evidence_size": source.get("size"),
                "evidence_fingerprint": source.get("fingerprint"),
                **command_limits,
            },
        }


def _session_snapshot(
    session_id: str,
    *,
    action: str,
    mode: str,
    state: str,
) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "action": action,
        "mode": mode,
        "state": state,
        "bounded": True,
    }


def _execution_kind(action: str, parameters: Mapping[str, Any]) -> str:
    if action in _PASSIVE_ACTIONS:
        return (
            "passive_capture_adapter"
            if parameters.get("capture_mode") == "adapter"
            else "passive_evidence_import"
        )
    if action == _HTTP_REPLAY:
        return "controlled_loopback_http_fixture_replay"
    if action in _REPLAY_ACTIONS:
        return (
            "offline_fixture_replay"
            if parameters.get("replay_target_mode") == "offline_fixture"
            else "loopback_controlled_replay"
        )
    if action == _HTTP_CAPTURE:
        return "real_loopback_http_capture"
    return "loopback_proxy_capture"


def _plan_network_transmit(action: str, parameters: Mapping[str, Any]) -> bool:
    if action in _PASSIVE_ACTIONS:
        return False
    if action in _REPLAY_ACTIONS:
        return parameters.get("replay_target_mode") != "offline_fixture"
    return True


def _plan_steps(action: str, parameters: Mapping[str, Any]) -> list[dict[str, str]]:
    if action in _PASSIVE_ACTIONS:
        capture_step = (
            "run_passive_loopback_capture_adapter"
            if parameters.get("capture_mode") == "adapter"
            else "import_bounded_passive_evidence"
        )
        names = [
            "validate_passive_no_transmit_boundary",
            "probe_capture_dependency",
            "verify_source_precondition",
            capture_step,
            "normalize_with_protocol_tools",
            "collect_protocol_evidence",
        ]
    elif action == _HTTP_CAPTURE:
        names = [
            "validate_real_loopback_http_boundary",
            "verify_precondition",
            "capture_http1_request_response_bytes",
            "verify_http_framing_and_integrity",
            "close_ephemeral_sockets",
            "collect_protocol_evidence",
        ]
    elif action == _HTTP_REPLAY:
        names = [
            "validate_controlled_loopback_http_fixture",
            "verify_capture_and_fixture_preconditions",
            "verify_source_http_integrity",
            "replay_exact_http1_fixture_transactions",
            "verify_response_and_endpoint_identity",
            "close_ephemeral_sockets",
            "collect_protocol_evidence",
        ]
    else:
        names = [
            "validate_explicit_endpoint_boundary",
            "verify_precondition",
            action,
            "close_ephemeral_sockets",
            "collect_protocol_evidence",
        ]
    return [{"step": name, "status": "planned"} for name in names]


def _validation_failure_status(
    plan: CapabilityPlan,
    validation: CapabilityValidation,
) -> str:
    if plan.action not in _PASSIVE_ACTIONS:
        return "failed"
    failed_names = {
        str(item.get("name") or "")
        for item in validation.checks
        if item.get("status") == "failed"
    }
    if "passive_capture_dependency" in failed_names:
        return "dependency-gated"
    if "capture_source" in failed_names:
        planned_source = _mapping(plan.before_snapshot.get("capture_source"))
        return "failed" if planned_source.get("is_file") else "unavailable"
    return "failed"


def _empty_after_snapshot(
    plan: CapabilityPlan,
    *,
    status: str,
    errors: Sequence[str],
) -> dict[str, Any]:
    dependency_probe = _mapping(plan.parameters.get("adapter_probe"))
    if status == "dependency-gated":
        dependency_state = "dependency-gated"
    elif plan.action in _PASSIVE_ACTIONS and plan.parameters.get("capture_mode") == "offline_import":
        dependency_state = "available"
        dependency_probe = {
            "status": "available",
            "adapter": "builtin_protocol_parser",
            "dependency_kind": "builtin",
            "real_adapter": True,
        }
    else:
        dependency_state = dependency_probe.get("status")
    return _prune(
        {
            "session_state": "closed",
            "session": _session_snapshot(
                plan.session_id,
                action=plan.action,
                mode=_execution_kind(plan.action, plan.parameters),
                state="closed",
            ),
            "side_effects": False,
            "network_transmit": False,
            "frame_count": 0,
            "frames": [],
            "flow_count": 0,
            "message_count": 0,
            "request_response_pair_count": 0,
            "capture_mode": plan.parameters.get("capture_mode"),
            "capture_source": _mapping(plan.before_snapshot.get("capture_source")),
            "dependency_state": dependency_state,
            "dependency_probe": dependency_probe,
            "network_boundary": _network_boundary(plan.parameters),
            "traffic_visibility": _tls_traffic_visibility(
                plan.parameters.get("tls")
            ),
            "outcome_class": status,
            "real_provider": True,
            "mock_provider": False,
            "real_capture_success": False,
            "errors": list(errors),
        }
    )


def _passive_precondition_hash(
    parameters: Mapping[str, Any],
    target: TargetIdentity,
    *,
    action: str,
) -> str:
    return _sha256_json(
        {
            "action": action,
            "target": _target_identity(target),
            "parameters": dict(parameters),
        }
    )


def _limit_errors(limits: Mapping[str, Any]) -> list[str]:
    ranges = {
        "duration_ms": (1, _MAX_DURATION_MS),
        "socket_timeout_ms": (1, _MAX_SOCKET_TIMEOUT_MS),
        "max_bytes": (1, _MAX_BYTES),
        "max_frames": (1, _MAX_FRAMES),
        "max_connections": (1, _MAX_CONNECTIONS),
        "max_packets": (1, _MAX_PACKETS),
        "max_messages": (1, _MAX_MESSAGES),
        "max_message_bytes": (1, _MAX_MESSAGE_BYTES),
        "max_stream_bytes": (1, _MAX_STREAM_BYTES),
        "max_correlation_messages": (1, _MAX_CORRELATION_MESSAGES),
        "max_request_response_pairs": (1, _MAX_REQUEST_RESPONSE_PAIRS),
        "max_http_header_bytes": (1, _MAX_HTTP_HEADER_BYTES),
        "max_http_headers": (1, _MAX_HTTP_HEADERS),
    }
    errors: list[str] = []
    for name, (minimum, maximum) in ranges.items():
        value = limits.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            errors.append(f"{name} must be between {minimum} and {maximum}")
    return errors


def _validate_endpoint(
    endpoint: Mapping[str, Any],
    *,
    allow_zero_port: bool,
    allow_remote: bool = False,
) -> tuple[bool, str]:
    host = str(endpoint.get("host") or "")
    accepted, reason = _endpoint_literal(host, allow_remote=allow_remote)
    if not accepted:
        return False, reason
    port = endpoint.get("port")
    minimum = 0 if allow_zero_port else 1
    if not isinstance(port, int) or isinstance(port, bool) or not minimum <= port <= 65_535:
        return False, f"port must be between {minimum} and 65535"
    return True, ""


def _endpoint_literal(host: str, *, allow_remote: bool) -> tuple[bool, str]:
    if not host:
        return False, "an explicit loopback IP address is required"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False, "host must be an IP literal; hostnames and DNS resolution are disabled"
    if address.is_loopback:
        return True, ""
    if not allow_remote:
        return False, "host must be in 127.0.0.0/8 or equal to ::1 unless allow_remote=true"
    if address.is_unspecified:
        return False, "unspecified addresses are not valid remote endpoints"
    if address.is_multicast:
        return False, "multicast addresses are not valid remote endpoints"
    if address.version == 4 and address == ipaddress.ip_address("255.255.255.255"):
        return False, "the IPv4 broadcast address is not a valid remote endpoint"
    return True, ""


def _remote_endpoints(endpoints: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    remote: list[dict[str, Any]] = []
    for endpoint in endpoints:
        try:
            address = ipaddress.ip_address(str(endpoint.get("host") or ""))
        except ValueError:
            continue
        if not address.is_loopback:
            remote.append(dict(endpoint))
    return remote


def _network_boundary(parameters: Mapping[str, Any]) -> str:
    declared = str(parameters.get("network_boundary") or "")
    if declared:
        return declared
    return (
        "explicit_ip_remote_opt_in"
        if parameters.get("allow_remote") is True
        else "explicit_loopback_ip_only"
    )


def _target_endpoint(parameters: Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(parameters.get("upstream_endpoint"), Mapping):
        return _mapping(parameters.get("upstream_endpoint"))
    endpoint = _mapping(parameters.get("destination_endpoint"))
    if not str(endpoint.get("host") or ""):
        return {}
    return endpoint


def _tls_audit_config(value: Any) -> dict[str, Any]:
    config = _mapping(value)
    return _prune(
        {
            "enabled": bool(config.get("enabled")),
            "mode": str(config.get("mode") or "client"),
            "verify": bool(config.get("verify")),
            "server_hostname": config.get("server_hostname"),
            "ca_file_configured": bool(config.get("ca_file")),
            "ca_file_sha256": config.get("ca_file_sha256"),
            "ca_file_size": config.get("ca_file_size"),
            "minimum_version": config.get("minimum_version"),
        }
    )


def _tls_traffic_visibility(value: Any) -> dict[str, Any]:
    enabled = bool(_mapping(value).get("enabled"))
    if enabled:
        application_bytes = "visible_at_provider_managed_tls_endpoint"
        decryption_scope = "provider_terminated_connection_only"
    else:
        application_bytes = "visible_on_plaintext_runtime_socket"
        decryption_scope = "not_applicable"
    return {
        "tls_enabled": enabled,
        "capture_layer": "application_socket_bytes",
        "application_bytes": application_bytes,
        "wire_tls_records_captured": False,
        "decryption": {
            "scope": decryption_scope,
            "unmanaged_or_external_sessions_supported": False,
            "private_or_session_keys_recorded": False,
        },
    }


def _tls_config_errors(config: Mapping[str, Any], *, transport: str) -> list[str]:
    errors: list[str] = []
    enabled = config.get("enabled")
    verify = config.get("verify")
    if not isinstance(enabled, bool):
        errors.append("TLS enabled must be a boolean")
    if not isinstance(verify, bool):
        errors.append("TLS verify must be a boolean")
    if config.get("mode") != "client":
        errors.append("only client-side TLS is supported")
    if config.get("minimum_version") != "TLSv1_2":
        errors.append("TLS minimum_version must be TLSv1_2")
    if not enabled:
        return errors
    if transport != "tcp":
        errors.append("TLS is supported only for TCP capture and replay")
    server_hostname = config.get("server_hostname")
    if not isinstance(server_hostname, str) or not server_hostname:
        errors.append("TLS server_hostname is required")
    elif "\x00" in server_hostname or len(server_hostname) > 253:
        errors.append("TLS server_hostname is invalid")
    ca_file = str(config.get("ca_file") or "")
    if ca_file:
        snapshot = _file_snapshot(ca_file)
        if not snapshot.get("is_file") or snapshot.get("error"):
            errors.append("TLS CA file must be a readable bounded file")
        planned_hash = str(config.get("ca_file_sha256") or "")
        if not planned_hash:
            errors.append("TLS CA file did not have a planning-time hash")
        elif str(snapshot.get("sha256") or "").lower() != planned_hash.lower():
            errors.append("TLS CA file changed after planning")
        planned_size = config.get("ca_file_size")
        if planned_size != snapshot.get("size"):
            errors.append("TLS CA file size changed after planning")
    return _deduplicate(errors)


def _public_parameters(parameters: Mapping[str, Any]) -> dict[str, Any]:
    public = dict(parameters)
    public["tls"] = _tls_audit_config(public.get("tls"))
    return _prune(public)


def _loopback_literal(host: str) -> tuple[bool, str]:
    return _endpoint_literal(host, allow_remote=False)


def _endpoint_key(endpoint: Mapping[str, Any]) -> tuple[str, int]:
    host = str(ipaddress.ip_address(str(endpoint.get("host") or "")))
    return host, int(endpoint.get("port") or 0)


def _endpoint_identity(endpoint: Mapping[str, Any]) -> dict[str, Any]:
    host = str(endpoint.get("host") or "")
    port = endpoint.get("port")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return _prune(
            {
                "host": host,
                "port": port,
                "ip_literal": False,
                "identity_sha256": _sha256_json({"host": host, "port": port}),
            }
        )
    normalized = str(address)
    identity = {
        "host": normalized,
        "port": port,
        "ip_literal": True,
        "ip_version": address.version,
        "address_family": "IPv6" if address.version == 6 else "IPv4",
        "loopback": address.is_loopback,
    }
    identity["identity_sha256"] = _sha256_json(identity)
    return identity


def _validated_mutation(value: Any) -> tuple[dict[str, Any], list[str]]:
    raw = _mapping(value)
    if not raw:
        return {"enabled": False}, []
    direction = str(raw.get("direction") or "client_to_server")
    find_hex = str(raw.get("find_hex") or raw.get("before_hex") or "")
    replace_hex = str(raw.get("replace_hex") or raw.get("after_hex") or "")
    max_replacements = _int_value(raw.get("max_replacements"), 1)
    errors: list[str] = []
    if direction not in _DIRECTIONS and direction != "both":
        errors.append("mutation direction must be client_to_server, server_to_client, or both")
    try:
        find = bytes.fromhex(find_hex)
    except ValueError:
        find = b""
        errors.append("mutation find_hex must contain valid hexadecimal bytes")
    try:
        replacement = bytes.fromhex(replace_hex)
    except ValueError:
        replacement = b""
        errors.append("mutation replace_hex must contain valid hexadecimal bytes")
    if not find:
        errors.append("mutation find_hex must not be empty")
    if len(find) > _MAX_MUTATION_PATTERN_BYTES or len(replacement) > _MAX_MUTATION_PATTERN_BYTES:
        errors.append("mutation pattern exceeds the bounded pattern size")
    if len(find) != len(replacement):
        errors.append("controlled mutation requires equal-length before and after bytes")
    if not 1 <= max_replacements <= 128:
        errors.append("max_replacements must be between 1 and 128")
    return (
        {
            "enabled": True,
            "direction": direction,
            "find_hex": find.hex(),
            "replace_hex": replacement.hex(),
            "max_replacements": max_replacements,
            "equal_length": len(find) == len(replacement),
        },
        errors,
    )


def _capture_precondition_hash(
    parameters: Mapping[str, Any],
    target: TargetIdentity,
    *,
    action: str = _CAPTURE,
) -> str:
    return _sha256_json(
        {
            "action": action,
            "target": _target_identity(target),
            "parameters": dict(parameters),
        }
    )


def _replay_precondition_hash(
    parameters: Mapping[str, Any],
    target: TargetIdentity,
    artifact_sha256: Any,
    *,
    action: str = _REPLAY,
) -> str:
    normalized_parameters = dict(parameters)
    normalized_parameters["capture_artifact_sha256"] = artifact_sha256
    return _sha256_json(
        {
            "action": action,
            "target": _target_identity(target),
            "parameters": normalized_parameters,
        }
    )


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_snapshot(value: Any) -> dict[str, Any]:
    path = Path(str(value or "")).expanduser()
    resolved = path.resolve()
    result: dict[str, Any] = {
        "path": str(resolved),
        "exists": resolved.exists(),
        "is_file": resolved.is_file(),
    }
    if not result["is_file"]:
        return result
    try:
        digest = hashlib.sha256()
        size = 0
        with resolved.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                size += len(chunk)
                if size > _MAX_ARTIFACT_BYTES:
                    result.update({"size": size, "error": "artifact exceeds read limit"})
                    return result
                digest.update(chunk)
        result.update({"size": size, "sha256": digest.hexdigest()})
    except OSError as exc:
        result["error"] = str(exc)
    return result


def _load_json_artifact(path: Path) -> tuple[dict[str, Any], str]:
    data = path.read_bytes()
    if len(data) > _MAX_ARTIFACT_BYTES:
        raise ValueError(f"capture artifact exceeds {_MAX_ARTIFACT_BYTES} bytes")
    payload = json.loads(data.decode("utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("capture artifact must contain a JSON object")
    return dict(payload), hashlib.sha256(data).hexdigest()


def _parse_http1_message(
    data: bytes,
    offset: int,
    *,
    kind: str,
    limits: Mapping[str, Any],
    request_method: str = "",
    stream_closed: bool,
) -> tuple[dict[str, Any], int]:
    if kind not in {"request", "response"}:
        raise ValueError("HTTP message kind must be request or response")
    max_header_bytes = int(limits.get("max_http_header_bytes") or 0)
    max_headers = int(limits.get("max_http_headers") or 0)
    max_message_bytes = min(
        int(limits.get("max_message_bytes") or 0),
        int(limits.get("max_stream_bytes") or 0),
    )
    marker = data.find(b"\r\n\r\n", offset)
    if marker < 0:
        if len(data) - offset > max_header_bytes:
            raise ValueError("HTTP header block exceeds max_http_header_bytes")
        raise _HttpNeedMoreData("HTTP header terminator is missing")
    body_start = marker + 4
    header_block = data[offset:body_start]
    if len(header_block) > max_header_bytes:
        raise ValueError("HTTP header block exceeds max_http_header_bytes")
    header_without_terminator = data[offset:marker]
    if b"\n" in header_without_terminator.replace(b"\r\n", b"") or b"\r" in (
        header_without_terminator.replace(b"\r\n", b"")
    ):
        raise ValueError("HTTP message contains a bare CR or LF")
    lines = header_without_terminator.split(b"\r\n")
    if not lines or not lines[0]:
        raise ValueError("HTTP start line is missing")
    try:
        start_line = lines[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("HTTP start line must be ASCII") from exc
    headers = _parse_http_header_lines(lines[1:], max_headers=max_headers)
    by_name: dict[str, list[str]] = {}
    for header in headers:
        by_name.setdefault(str(header["name_lower"]), []).append(str(header["value"]))

    message: dict[str, Any] = {
        "kind": f"http_{kind}",
        "protocol": "http",
        "http_version": "HTTP/1.1",
        "start_line": start_line,
        "direction": "client_to_server" if kind == "request" else "server_to_client",
    }
    if kind == "request":
        parts = lines[0].split(b" ")
        if len(parts) != 3 or not all(parts):
            raise ValueError("HTTP/1.1 request line must contain method, target, and version")
        method_raw, target_raw, version_raw = parts
        if not _HTTP_METHOD_RE.fullmatch(method_raw):
            raise ValueError("HTTP request method is invalid")
        if version_raw != b"HTTP/1.1":
            raise ValueError("only HTTP/1.1 request evidence is supported")
        if any(value <= 0x20 or value == 0x7F for value in target_raw):
            raise ValueError("HTTP request target contains invalid whitespace or control bytes")
        try:
            method = method_raw.decode("ascii")
            request_target = target_raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("HTTP request method and target must be ASCII") from exc
        hosts = by_name.get("host", [])
        if len(hosts) != 1 or not hosts[0].strip():
            raise ValueError("HTTP/1.1 request must contain exactly one non-empty Host header")
        message.update({"method": method, "request_target": request_target})
        status_code: Optional[int] = None
    else:
        parts = lines[0].split(b" ", 2)
        if len(parts) < 2 or parts[0] != b"HTTP/1.1":
            raise ValueError("only HTTP/1.1 response evidence is supported")
        if len(parts[1]) != 3 or not parts[1].isdigit():
            raise ValueError("HTTP response status code is invalid")
        status_code = int(parts[1])
        if not 100 <= status_code <= 999:
            raise ValueError("HTTP response status code is outside the three-digit range")
        reason_raw = parts[2] if len(parts) == 3 else b""
        if any(value < 0x20 and value != 0x09 for value in reason_raw) or b"\x7f" in reason_raw:
            raise ValueError("HTTP response reason phrase contains control bytes")
        message.update(
            {
                "status_code": status_code,
                "reason": reason_raw.decode("iso-8859-1"),
                "request_method": request_method,
            }
        )

    content_length = _http_content_length(by_name.get("content-length", []))
    transfer_encoding = _http_transfer_encoding(by_name.get("transfer-encoding", []))
    if content_length is not None and transfer_encoding:
        raise ValueError("HTTP message contains both Transfer-Encoding and Content-Length")
    if transfer_encoding and transfer_encoding != ["chunked"]:
        raise ValueError("HTTP replay evidence supports only a final chunked transfer coding")
    connection_tokens = _http_comma_tokens(by_name.get("connection", []))

    no_body = False
    no_body_reason: Optional[str] = None
    if kind == "response" and status_code is not None:
        method_upper = request_method.upper()
        if method_upper == "HEAD":
            no_body = True
            no_body_reason = "head_response"
        elif 100 <= status_code < 200:
            no_body = True
            no_body_reason = "informational_status"
        elif status_code == 204:
            no_body = True
            no_body_reason = "status_204"
        elif status_code == 304:
            no_body = True
            no_body_reason = "status_304"
        elif method_upper == "CONNECT" and 200 <= status_code < 300:
            no_body = True
            no_body_reason = "connect_tunnel"
        if status_code == 204 and (content_length is not None or transfer_encoding):
            raise ValueError("HTTP 204 response must not contain body framing headers")
        if 100 <= status_code < 200 and transfer_encoding:
            raise ValueError("HTTP informational response must not contain Transfer-Encoding")

    trailers: list[dict[str, str]] = []
    trailer_wire = b""
    if no_body:
        framing_type = "no_body"
        body = b""
        body_wire = b""
        end = body_start
    elif transfer_encoding:
        framing_type = "chunked"
        body, end, trailers, trailer_wire = _parse_http1_chunked_body(
            data,
            body_start,
            limits=limits,
        )
        body_wire = data[body_start:end]
    elif content_length is not None:
        framing_type = "content_length"
        if content_length > max_message_bytes:
            raise ValueError("HTTP Content-Length exceeds the message/stream byte budget")
        end = body_start + content_length
        if len(data) < end:
            raise _HttpNeedMoreData("HTTP Content-Length body is truncated")
        body = data[body_start:end]
        body_wire = body
    elif kind == "request":
        framing_type = "no_body"
        body = b""
        body_wire = b""
        end = body_start
        no_body_reason = "request_without_body_framing"
    else:
        framing_type = "connection_close"
        if not stream_closed:
            raise _HttpNeedMoreData("HTTP close-delimited response has not reached EOF")
        body = data[body_start:]
        body_wire = body
        end = len(data)

    wire = data[offset:end]
    if len(wire) > max_message_bytes:
        raise ValueError("HTTP message exceeds the message/stream byte budget")
    if len(body) > max_message_bytes:
        raise ValueError("HTTP decoded body exceeds the message/stream byte budget")
    raw_headers = b"\r\n".join(lines[1:])
    normalized_headers = [
        {"name": item["name_lower"], "value": item["value"]} for item in headers
    ]
    header_evidence = {
        "count": len(headers),
        "wire_length": len(raw_headers),
        "wire_sha256": hashlib.sha256(raw_headers).hexdigest(),
        "block_length": len(header_block),
        "block_sha256": hashlib.sha256(header_block).hexdigest(),
        "normalized_sha256": _sha256_json(normalized_headers),
    }
    body_evidence = {
        "length": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "wire_length": len(body_wire),
        "wire_sha256": hashlib.sha256(body_wire).hexdigest(),
    }
    framing = _prune(
        {
            "type": framing_type,
            "complete": True,
            "header_terminator": "CRLFCRLF",
            "content_length": content_length,
            "transfer_encoding": transfer_encoding,
            "connection_close": "close" in connection_tokens,
            "no_body_reason": no_body_reason,
            "header_bytes": len(header_block),
            "body_wire_bytes": len(body_wire),
            "body_decoded_bytes": len(body),
            "message_bytes": len(wire),
            "trailer_count": len(trailers),
            "trailer_wire_sha256": hashlib.sha256(trailer_wire).hexdigest(),
        }
    )
    message.update(
        {
            "headers": headers,
            "header_count": len(headers),
            "header_evidence": header_evidence,
            "headers_sha256": header_evidence["wire_sha256"],
            "normalized_headers_sha256": header_evidence["normalized_sha256"],
            "trailers": trailers,
            "body": body_evidence,
            "body_length": len(body),
            "body_sha256": body_evidence["sha256"],
            "body_wire_sha256": body_evidence["wire_sha256"],
            "framing": framing,
            "wire_length": len(wire),
            "wire_sha256": hashlib.sha256(wire).hexdigest(),
            "length": len(wire),
            "sha256": hashlib.sha256(wire).hexdigest(),
            "payload_base64": base64.b64encode(wire).decode("ascii"),
            "source_integrity": {
                "complete": True,
                "payload_truncated": False,
                "reassembly_gap_count": 0,
                "damaged": False,
            },
        }
    )
    return _prune(message), end


def _parse_http_header_lines(
    lines: Sequence[bytes],
    *,
    max_headers: int,
) -> list[dict[str, str]]:
    if len(lines) > max_headers:
        raise ValueError("HTTP header count exceeds max_http_headers")
    headers: list[dict[str, str]] = []
    for line in lines:
        if not line:
            raise ValueError("HTTP header block contains an unexpected empty line")
        if line[:1] in {b" ", b"\t"}:
            raise ValueError("obsolete folded HTTP headers are not accepted")
        if b":" not in line:
            raise ValueError("HTTP header line has no colon separator")
        name_raw, value_raw = line.split(b":", 1)
        if not _HTTP_TOKEN_RE.fullmatch(name_raw):
            raise ValueError("HTTP header field name is invalid")
        value_raw = value_raw.strip(b" \t")
        if any(value < 0x20 and value != 0x09 for value in value_raw) or b"\x7f" in value_raw:
            raise ValueError("HTTP header field value contains control bytes")
        name = name_raw.decode("ascii")
        headers.append(
            {
                "name": name,
                "name_lower": name.lower(),
                "value": value_raw.decode("iso-8859-1"),
            }
        )
    return headers


def _http_content_length(values: Sequence[str]) -> Optional[int]:
    if not values:
        return None
    parsed: list[int] = []
    for value in values:
        for item in value.split(","):
            text = item.strip()
            if not text or not text.isascii() or not text.isdigit():
                raise ValueError("HTTP Content-Length is invalid")
            parsed.append(int(text))
    if not parsed or any(item != parsed[0] for item in parsed[1:]):
        raise ValueError("HTTP Content-Length values conflict")
    return parsed[0]


def _http_transfer_encoding(values: Sequence[str]) -> list[str]:
    tokens = _http_comma_tokens(values)
    if values and not tokens:
        raise ValueError("HTTP Transfer-Encoding is empty")
    for item in tokens:
        try:
            encoded = item.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(
                "HTTP Transfer-Encoding contains a non-ASCII coding"
            ) from exc
        if ";" in item or not _HTTP_TOKEN_RE.fullmatch(encoded):
            raise ValueError("HTTP Transfer-Encoding contains an invalid coding")
    if tokens and tokens[-1] != "chunked":
        raise ValueError("HTTP Transfer-Encoding must end in chunked")
    return tokens


def _http_comma_tokens(values: Sequence[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        result.extend(item.strip().lower() for item in value.split(",") if item.strip())
    return result


def _parse_http1_chunked_body(
    data: bytes,
    offset: int,
    *,
    limits: Mapping[str, Any],
) -> tuple[bytes, int, list[dict[str, str]], bytes]:
    cursor = offset
    body = bytearray()
    max_header_bytes = int(limits.get("max_http_header_bytes") or 0)
    max_headers = int(limits.get("max_http_headers") or 0)
    max_message_bytes = min(
        int(limits.get("max_message_bytes") or 0),
        int(limits.get("max_stream_bytes") or 0),
    )
    while True:
        line_end = data.find(b"\r\n", cursor)
        if line_end < 0:
            raise _HttpNeedMoreData("HTTP chunk-size line is truncated")
        if line_end - cursor > max_header_bytes:
            raise ValueError("HTTP chunk-size line exceeds max_http_header_bytes")
        size_line = data[cursor:line_end]
        size_token = size_line.split(b";", 1)[0].strip()
        if not size_token or not re.fullmatch(rb"[0-9A-Fa-f]+", size_token):
            raise ValueError("HTTP chunk size is invalid")
        chunk_size = int(size_token, 16)
        cursor = line_end + 2
        if chunk_size == 0:
            if data[cursor : cursor + 2] == b"\r\n":
                return bytes(body), cursor + 2, [], b""
            trailer_end = data.find(b"\r\n\r\n", cursor)
            if trailer_end < 0:
                if len(data) - cursor > max_header_bytes:
                    raise ValueError("HTTP trailer block exceeds max_http_header_bytes")
                raise _HttpNeedMoreData("HTTP chunk trailer terminator is missing")
            trailer_wire = data[cursor:trailer_end]
            if len(trailer_wire) > max_header_bytes:
                raise ValueError("HTTP trailer block exceeds max_http_header_bytes")
            trailer_lines = trailer_wire.split(b"\r\n") if trailer_wire else []
            trailers = _parse_http_header_lines(
                trailer_lines,
                max_headers=max_headers,
            )
            prohibited = {"content-length", "host", "transfer-encoding"}
            if any(item["name_lower"] in prohibited for item in trailers):
                raise ValueError("HTTP trailer contains a prohibited framing field")
            return bytes(body), trailer_end + 4, trailers, trailer_wire
        if chunk_size > max_message_bytes or len(body) + chunk_size > max_message_bytes:
            raise ValueError("HTTP chunked body exceeds the message/stream byte budget")
        chunk_end = cursor + chunk_size
        if len(data) < chunk_end + 2:
            raise _HttpNeedMoreData("HTTP chunk data is truncated")
        if data[chunk_end : chunk_end + 2] != b"\r\n":
            raise ValueError("HTTP chunk data is not terminated by CRLF")
        body.extend(data[cursor:chunk_end])
        cursor = chunk_end + 2


def _build_http_capture_evidence(
    frames: Sequence[Any],
    connections: Sequence[Any],
    limits: Mapping[str, Any],
    *,
    raw_limit_reached: Any,
) -> dict[str, Any]:
    streams: OrderedDict[str, dict[str, bytearray]] = OrderedDict()
    errors: list[str] = []
    gap_count = 0
    damaged = False
    expected_sequence = 1
    for index, item in enumerate(frames, start=1):
        if not isinstance(item, Mapping):
            errors.append(f"HTTP capture frame {index} is not an object")
            gap_count += 1
            damaged = True
            continue
        frame = dict(item)
        sequence = frame.get("sequence")
        if sequence != expected_sequence:
            errors.append(
                f"HTTP capture frame sequence gap: expected {expected_sequence}, got {sequence}"
            )
            gap_count += 1
        expected_sequence = index + 1
        connection_id = str(frame.get("connection_id") or "")
        direction = str(frame.get("direction") or "")
        if not connection_id or direction not in _DIRECTIONS:
            errors.append(f"HTTP capture frame {index} has invalid routing identity")
            gap_count += 1
            damaged = True
            continue
        if str(frame.get("transport") or "tcp").lower() != "tcp":
            errors.append(f"HTTP capture frame {index} is not TCP evidence")
            damaged = True
            continue
        try:
            payload = _frame_payload(frame)
        except ValueError as exc:
            errors.append(f"HTTP capture frame {index}: {exc}")
            damaged = True
            continue
        if frame.get("length") != len(payload):
            errors.append(f"HTTP capture frame {index} length does not match payload")
            damaged = True
            continue
        if str(frame.get("sha256") or "").lower() != hashlib.sha256(payload).hexdigest():
            errors.append(f"HTTP capture frame {index} hash does not match payload")
            damaged = True
            continue
        streams.setdefault(
            connection_id,
            {"client_to_server": bytearray(), "server_to_client": bytearray()},
        )[direction].extend(payload)

    records = {
        str(_mapping(item).get("connection_id") or ""): dict(_mapping(item))
        for item in connections
    }
    messages: list[dict[str, Any]] = []
    pairs: list[dict[str, Any]] = []
    sessions: list[dict[str, Any]] = []
    tunnels: list[dict[str, Any]] = []
    framing_counts: dict[str, int] = {}
    truncated = bool(raw_limit_reached)
    for connection_id, directions in streams.items():
        max_stream_bytes = int(limits.get("max_stream_bytes") or 0)
        if any(len(stream) > max_stream_bytes for stream in directions.values()):
            errors.append(
                f"HTTP connection {connection_id} exceeds max_stream_bytes"
            )
            truncated = True
        exchange = _parse_http1_exchange(
            connection_id,
            bytes(directions["client_to_server"]),
            bytes(directions["server_to_client"]),
            limits,
        )
        record = records.get(connection_id, {})
        connection_messages = list(exchange.get("messages") or [])
        for message in connection_messages:
            message["sequence"] = len(messages) + 1
            messages.append(message)
            framing_type = str(_mapping(message.get("framing")).get("type") or "unknown")
            framing_counts[framing_type] = framing_counts.get(framing_type, 0) + 1
        for pair in exchange.get("request_response_pairs") or []:
            pair["sequence"] = len(pairs) + 1
            pairs.append(pair)
        for tunnel in exchange.get("connect_tunnels") or []:
            request = next(
                (
                    item
                    for item in connection_messages
                    if str(item.get("kind") or "") == "http_request"
                    and str(item.get("method") or "").upper() == "CONNECT"
                ),
                {},
            )
            response = next(
                (
                    item
                    for item in connection_messages
                    if str(item.get("kind") or "") == "http_response"
                    and 200 <= int(item.get("status_code") or 0) < 300
                ),
                {},
            )
            client_payload, client_errors = _opaque_tunnel_payload(
                tunnel.get("client_to_server"),
                direction="client_to_server",
            )
            server_payload, server_errors = _opaque_tunnel_payload(
                tunnel.get("server_to_client"),
                direction="server_to_client",
            )
            tunnel_frames, frame_errors = _connect_tunnel_source_frames(
                frames,
                connection_id=connection_id,
                request_wire=_http_message_wire(request),
                response_wire=_http_message_wire(response),
                client_payload=client_payload,
                server_payload=server_payload,
            )
            half_close_events, half_close_errors = _connect_half_close_events(
                record.get("half_close_events"),
                tunnel_frames=tunnel_frames,
            )
            authority_endpoint, authority_errors = _connect_authority_endpoint(
                tunnel.get("authority")
            )
            tunnel.update(
                {
                    "authority_endpoint": authority_endpoint,
                    "authority_endpoint_identity": _endpoint_identity(authority_endpoint),
                    "transcript": _connect_transcript_evidence(tunnel_frames),
                    "half_close_events": half_close_events,
                    "half_close_verified": bool(half_close_events)
                    and not half_close_errors,
                }
            )
            errors.extend(
                [
                    *client_errors,
                    *server_errors,
                    *frame_errors,
                    *half_close_errors,
                    *authority_errors,
                ]
            )
            tunnel["sequence"] = len(tunnels) + 1
            tunnels.append(tunnel)
        exchange_errors = list(exchange.get("errors") or [])
        errors.extend(exchange_errors)
        gap_count += int(exchange.get("gap_count") or 0)
        truncated = truncated or bool(exchange.get("truncated"))
        damaged = damaged or bool(exchange.get("damaged"))
        sessions.append(
            _prune(
                {
                    "connection_id": connection_id,
                    "complete": bool(exchange.get("complete")),
                    "request_count": int(exchange.get("request_count") or 0),
                    "response_count": int(exchange.get("response_count") or 0),
                    "request_response_pair_count": len(
                        exchange.get("request_response_pairs") or []
                    ),
                    "connect_tunnel_count": len(
                        exchange.get("connect_tunnels") or []
                    ),
                    "connect_tunnels": list(exchange.get("connect_tunnels") or []),
                    "client_stream_bytes": len(directions["client_to_server"]),
                    "server_stream_bytes": len(directions["server_to_client"]),
                    "peer": record.get("peer"),
                    "client_socket_identity": record.get("client_socket_identity"),
                    "upstream_endpoint": record.get("upstream"),
                    "upstream_socket_identity": record.get("upstream_socket_identity"),
                    "tls": record.get("tls"),
                    "errors": exchange_errors,
                }
            )
        )

    if len(messages) > int(limits.get("max_messages") or 0):
        errors.append("HTTP capture messages exceed max_messages")
        truncated = True
    if len(messages) > int(limits.get("max_correlation_messages") or 0):
        errors.append("HTTP capture messages exceed max_correlation_messages")
        truncated = True
    if len(pairs) > int(limits.get("max_request_response_pairs") or 0):
        errors.append("HTTP capture transactions exceed max_request_response_pairs")
        truncated = True
    real_connections = [records.get(connection_id, {}) for connection_id in streams]
    real_socket_evidence = bool(real_connections) and all(
        _capture_connection_has_real_loopback_identity(item) for item in real_connections
    )
    complete = (
        bool(pairs)
        and not errors
        and not truncated
        and gap_count == 0
        and not damaged
        and all(bool(item.get("complete")) for item in sessions)
    )
    integrity = {
        "complete": complete,
        "truncated": truncated,
        "gap_count": gap_count,
        "tampered": damaged,
        "damaged": damaged,
        "raw_limit_reached": raw_limit_reached,
        "fail_closed": not complete,
        "errors": _deduplicate(errors),
    }
    return {
        "complete": complete,
        "real_socket_evidence": real_socket_evidence,
        "messages": messages,
        "request_response_pairs": pairs,
        "connect_tunnels": tunnels,
        "sessions": sessions,
        "framing": {
            "protocol": "HTTP/1.1",
            "strict_crlf": True,
            "framing_counts": framing_counts,
            "header_hashes": True,
            "body_hashes": True,
            "wire_hashes": True,
        },
        "integrity": integrity,
        "errors": _deduplicate(errors),
    }


def _capture_connection_has_real_loopback_identity(value: Mapping[str, Any]) -> bool:
    if value.get("status") != "closed":
        return False
    for name in ("client_socket_identity", "upstream_socket_identity"):
        identity = _mapping(value.get(name))
        if identity.get("real_socket") is not True or identity.get("synthetic") is not False:
            return False
        local = _mapping(identity.get("local"))
        peer = _mapping(identity.get("peer"))
        if local.get("loopback") is not True or peer.get("loopback") is not True:
            return False
    return True


def _parse_http1_exchange(
    connection_id: str,
    request_stream: bytes,
    response_stream: bytes,
    limits: Mapping[str, Any],
) -> dict[str, Any]:
    requests: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    errors: list[str] = []
    gap_count = 0
    truncated = False
    damaged = False
    request_offset = 0
    request_tunnel_bytes = b""
    while request_offset < len(request_stream):
        if len(requests) >= int(limits.get("max_messages") or 0):
            errors.append("HTTP request stream exceeds max_messages")
            truncated = True
            break
        try:
            request, request_offset = _parse_http1_message(
                request_stream,
                request_offset,
                kind="request",
                limits=limits,
                stream_closed=True,
            )
        except _HttpNeedMoreData as exc:
            errors.append(f"HTTP request stream is truncated: {exc}")
            truncated = True
            gap_count += 1
            break
        except ValueError as exc:
            errors.append(f"HTTP request stream is malformed: {exc}")
            damaged = True
            gap_count += 1
            break
        request["connection_id"] = connection_id
        request["id"] = f"{connection_id}-request-{len(requests) + 1}"
        requests.append(request)
        if str(request.get("method") or "").upper() == "CONNECT":
            request_tunnel_bytes = request_stream[request_offset:]
            request_offset = len(request_stream)
            break

    response_offset = 0
    request_index = 0
    pending_interim: list[dict[str, Any]] = []
    pairs: list[dict[str, Any]] = []
    connect_tunnels: list[dict[str, Any]] = []
    while response_offset < len(response_stream):
        if len(requests) + len(responses) >= int(limits.get("max_messages") or 0):
            errors.append("HTTP response stream exceeds max_messages")
            truncated = True
            break
        method = str(requests[request_index].get("method") or "") if request_index < len(requests) else ""
        try:
            response, response_offset = _parse_http1_message(
                response_stream,
                response_offset,
                kind="response",
                request_method=method,
                limits=limits,
                stream_closed=True,
            )
        except _HttpNeedMoreData as exc:
            errors.append(f"HTTP response stream is truncated: {exc}")
            truncated = True
            gap_count += 1
            break
        except ValueError as exc:
            errors.append(f"HTTP response stream is malformed: {exc}")
            damaged = True
            gap_count += 1
            break
        response["connection_id"] = connection_id
        response["id"] = f"{connection_id}-response-{len(responses) + 1}"
        responses.append(response)
        status_code = int(response.get("status_code") or 0)
        if 100 <= status_code < 200 and status_code != 101:
            pending_interim.append(response)
            continue
        if request_index >= len(requests):
            errors.append("HTTP response has no corresponding request")
            gap_count += 1
            continue
        request = requests[request_index]
        transaction_limitations = _http_transaction_limitations(request, response)
        is_connect = str(request.get("method") or "").upper() == "CONNECT"
        connect_established = is_connect and 200 <= status_code < 300
        response_tunnel_bytes = b""
        if connect_established:
            response_tunnel_bytes = response_stream[response_offset:]
            response_offset = len(response_stream)
            connect_tunnels.append(
                {
                    "id": f"{connection_id}-connect-tunnel-{len(connect_tunnels) + 1}",
                    "connection_id": connection_id,
                    "authority": request.get("request_target"),
                    "status_code": status_code,
                    "established": True,
                    "opaque_after_handshake": True,
                    "client_to_server": _opaque_tunnel_evidence(
                        request_tunnel_bytes
                    ),
                    "server_to_client": _opaque_tunnel_evidence(
                        response_tunnel_bytes
                    ),
                    "bidirectional_payload_observed": bool(request_tunnel_bytes)
                    and bool(response_tunnel_bytes),
                }
            )
        elif is_connect and request_tunnel_bytes:
            errors.append("HTTP CONNECT request carried tunnel bytes before a successful response")
            damaged = True
        pairs.append(
            _prune(
                {
                    "id": f"{connection_id}-transaction-{len(pairs) + 1}",
                    "connection_id": connection_id,
                    "request_message_id": request.get("id"),
                    "response_message_id": response.get("id"),
                    "interim_response_message_ids": [
                        item.get("id") for item in pending_interim
                    ],
                    "method": request.get("method"),
                    "request_target": request.get("request_target"),
                    "status_code": response.get("status_code"),
                    "request_wire_sha256": request.get("wire_sha256"),
                    "request_header_sha256": request.get("headers_sha256"),
                    "request_body_sha256": request.get("body_sha256"),
                    "response_wire_sha256": response.get("wire_sha256"),
                    "response_header_sha256": response.get("headers_sha256"),
                    "response_body_sha256": response.get("body_sha256"),
                    "complete": True,
                    "replay_supported": not transaction_limitations,
                    "limitations": transaction_limitations,
                }
            )
        )
        request_index += 1
        pending_interim = []
        if connect_established:
            break

    if pending_interim:
        errors.append("HTTP informational response has no final response")
        gap_count += 1
    if request_index < len(requests):
        missing = len(requests) - request_index
        errors.append(f"HTTP session is missing {missing} final response(s)")
        gap_count += missing
    if len(pairs) > int(limits.get("max_request_response_pairs") or 0):
        errors.append("HTTP session exceeds max_request_response_pairs")
        truncated = True
    complete = (
        bool(pairs)
        and not errors
        and not truncated
        and not damaged
        and request_index == len(requests)
    )
    return {
        "complete": complete,
        "request_count": len(requests),
        "response_count": len(responses),
        "messages": requests + responses,
        "request_response_pairs": pairs,
        "connect_tunnels": connect_tunnels,
        "gap_count": gap_count,
        "truncated": truncated,
        "damaged": damaged,
        "errors": _deduplicate(errors),
    }


def _opaque_tunnel_evidence(data: bytes) -> dict[str, Any]:
    """Describe post-CONNECT bytes without interpreting the tunneled protocol."""

    return {
        "length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "payload_base64": base64.b64encode(data).decode("ascii"),
    }


def _opaque_tunnel_payload(value: Any, *, direction: str) -> tuple[bytes, list[str]]:
    evidence = _mapping(value)
    errors: list[str] = []
    encoded = evidence.get("payload_base64")
    try:
        payload = base64.b64decode(str(encoded).encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        payload = b""
        errors.append(f"CONNECT {direction} payload_base64 is invalid")
    try:
        if int(evidence.get("length") or 0) != len(payload):
            errors.append(f"CONNECT {direction} payload length does not match")
    except (TypeError, ValueError, OverflowError):
        errors.append(f"CONNECT {direction} payload length is invalid")
    digest = str(evidence.get("sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        errors.append(f"CONNECT {direction} payload hash is invalid")
    elif digest != hashlib.sha256(payload).hexdigest():
        errors.append(f"CONNECT {direction} payload hash does not match")
    return payload, _deduplicate(errors)


def _connect_authority_endpoint(authority: Any) -> tuple[dict[str, Any], list[str]]:
    value = str(authority or "").strip()
    host = ""
    port_text = ""
    if value.startswith("[") and "]:" in value:
        host, _, port_text = value[1:].partition("]:")
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator:
            host = ""
    try:
        port = int(port_text)
    except (TypeError, ValueError, OverflowError):
        port = 0
    endpoint = {"host": host, "port": port}
    ok, reason = _validate_endpoint(
        endpoint,
        allow_zero_port=False,
        allow_remote=False,
    )
    return endpoint, [] if ok else [f"CONNECT authority is invalid: {reason}"]


def _connect_tunnel_source_frames(
    raw_frames: Sequence[Mapping[str, Any]],
    *,
    connection_id: str,
    request_wire: bytes,
    response_wire: bytes,
    client_payload: bytes,
    server_payload: bytes,
) -> tuple[list[dict[str, Any]], list[str]]:
    prefixes = {
        "client_to_server": request_wire,
        "server_to_client": response_wire,
    }
    consumed = {"client_to_server": 0, "server_to_client": 0}
    tunnel_frames: list[dict[str, Any]] = []
    errors: list[str] = []
    for frame in raw_frames:
        if str(frame.get("connection_id") or "") != connection_id:
            continue
        direction = str(frame.get("direction") or "")
        if direction not in prefixes:
            errors.append("CONNECT source frame direction is invalid")
            continue
        try:
            data = _frame_payload(frame)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        prefix = prefixes[direction]
        offset = consumed[direction]
        prefix_part = data[: max(0, len(prefix) - offset)]
        if prefix_part != prefix[offset : offset + len(prefix_part)]:
            errors.append(f"CONNECT {direction} frames do not match the HTTP handshake")
            continue
        consumed[direction] += len(prefix_part)
        opaque = data[len(prefix_part) :]
        if opaque:
            tunnel_frames.append(
                {
                    "source_sequence": frame.get("sequence"),
                    "direction": direction,
                    "length": len(opaque),
                    "sha256": hashlib.sha256(opaque).hexdigest(),
                    "payload_base64": base64.b64encode(opaque).decode("ascii"),
                }
            )
    for direction, prefix in prefixes.items():
        if consumed[direction] != len(prefix):
            errors.append(f"CONNECT {direction} handshake evidence is incomplete")
    observed = {"client_to_server": bytearray(), "server_to_client": bytearray()}
    for frame in tunnel_frames:
        observed[str(frame["direction"])].extend(_frame_payload(frame))
    if bytes(observed["client_to_server"]) != client_payload:
        errors.append("CONNECT client_to_server tunnel evidence does not match source frames")
    if bytes(observed["server_to_client"]) != server_payload:
        errors.append("CONNECT server_to_client tunnel evidence does not match source frames")
    return tunnel_frames, _deduplicate(errors)


def _connect_transcript_evidence(
    tunnel_frames: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    entries = [
        {
            "sequence": index,
            "source_sequence": frame.get("source_sequence"),
            "direction": str(frame.get("direction") or ""),
            "length": int(frame.get("length") or 0),
            "sha256": str(frame.get("sha256") or ""),
        }
        for index, frame in enumerate(tunnel_frames, start=1)
    ]
    canonical = json.dumps(
        entries,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "frame_count": len(entries),
        "client_to_server_frame_count": sum(
            1 for item in entries if item["direction"] == "client_to_server"
        ),
        "server_to_client_frame_count": sum(
            1 for item in entries if item["direction"] == "server_to_client"
        ),
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "frames": entries,
    }


def _connect_half_close_events(
    value: Any,
    *,
    tunnel_frames: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    raw_events = value if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else []
    source_sequences: set[int] = set()
    source_sequence_errors: list[str] = []
    for index, frame in enumerate(tunnel_frames, start=1):
        try:
            source_sequence = int(frame.get("source_sequence") or 0)
        except (TypeError, ValueError, OverflowError):
            source_sequence_errors.append(
                f"CONNECT tunnel frame {index} has an invalid source sequence"
            )
            continue
        if source_sequence > 0:
            source_sequences.add(source_sequence)
    events: list[dict[str, Any]] = []
    errors: list[str] = list(source_sequence_errors)
    seen_directions: set[str] = set()
    previous_after_frame_sequence = 0
    for index, item in enumerate(raw_events, start=1):
        if not isinstance(item, Mapping):
            errors.append(f"CONNECT half-close event {index} is not an object")
            continue
        event = dict(item)
        direction = str(event.get("direction") or "")
        try:
            sequence = int(event.get("sequence") or 0)
            after_frame_sequence = int(
                event.get("after_source_frame_sequence")
                or event.get("after_frame_sequence")
                or 0
            )
        except (TypeError, ValueError, OverflowError):
            errors.append(f"CONNECT half-close event {index} has invalid ordering")
            continue
        if sequence != index:
            errors.append(f"CONNECT half-close event {index} has a sequence gap")
        if direction not in _DIRECTIONS:
            errors.append(f"CONNECT half-close event {index} has an invalid direction")
            continue
        if direction in seen_directions:
            errors.append(f"CONNECT half-close direction {direction} is duplicated")
        seen_directions.add(direction)
        if after_frame_sequence not in source_sequences:
            errors.append(
                f"CONNECT half-close event {index} references an unknown source frame"
            )
            continue
        if after_frame_sequence < previous_after_frame_sequence:
            errors.append(f"CONNECT half-close event {index} is out of order")
        previous_after_frame_sequence = after_frame_sequence
        if event.get("propagated") is not True:
            errors.append(f"CONNECT half-close {direction} was not propagated")
        events.append(
            {
                "sequence": len(events) + 1,
                "direction": direction,
                "after_source_frame_sequence": after_frame_sequence,
                "mode": str(event.get("mode") or ""),
                "propagated": event.get("propagated") is True,
            }
        )
    missing_directions = sorted(_DIRECTIONS - seen_directions)
    if missing_directions:
        errors.append(
            "CONNECT half-close evidence is missing directions: "
            + ", ".join(missing_directions)
        )
    return events, _deduplicate(errors)


def _connect_transcript_errors(
    value: Any,
    *,
    tunnel_frames: Sequence[Mapping[str, Any]],
) -> list[str]:
    expected = _mapping(value)
    actual = _connect_transcript_evidence(tunnel_frames)
    errors: list[str] = []
    for name in (
        "frame_count",
        "client_to_server_frame_count",
        "server_to_client_frame_count",
        "sha256",
    ):
        if expected.get(name) != actual.get(name):
            errors.append(f"CONNECT transcript {name} does not match source frames")
    expected_frames = expected.get("frames")
    if not isinstance(expected_frames, list) or expected_frames != actual["frames"]:
        errors.append("CONNECT transcript frame order does not match source frames")
    return _deduplicate(errors)


def _http_transaction_limitations(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
) -> list[str]:
    limitations: list[str] = []
    method = str(request.get("method") or "").upper()
    status_code = int(response.get("status_code") or 0)
    request_connection = _http_message_header_tokens(request, "connection")
    response_connection = _http_message_header_tokens(response, "connection")
    if method == "CONNECT" and not 200 <= status_code < 300:
        limitations.append("CONNECT replay requires a successful 2xx handshake")
    if status_code == 101 or "upgrade" in request_connection or "upgrade" in response_connection:
        limitations.append("protocol upgrade replay is not generalized")
    return limitations


def _http_message_header_tokens(message: Mapping[str, Any], name: str) -> list[str]:
    values = [
        str(item.get("value") or "")
        for item in message.get("headers", [])
        if isinstance(item, Mapping) and str(item.get("name_lower") or "") == name
    ]
    return _http_comma_tokens(values)


def _resolved_http_fixture(value: Any) -> tuple[dict[str, Any], list[str]]:
    fixture = _mapping(value)
    if str(fixture.get("kind") or "") != "file":
        return fixture, []

    errors: list[str] = []
    snapshot = _file_snapshot(fixture.get("path"))
    if not snapshot.get("is_file") or snapshot.get("error"):
        return fixture, ["controlled HTTP fixture file is unavailable"]
    if str(snapshot.get("sha256") or "").lower() != str(
        fixture.get("sha256") or ""
    ).lower():
        errors.append("controlled HTTP fixture file changed after planning")
    if snapshot.get("size") != fixture.get("size"):
        errors.append("controlled HTTP fixture file size changed after planning")
    if errors:
        return fixture, errors

    try:
        payload, digest = _load_json_artifact(Path(str(snapshot["path"])))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return fixture, [
            f"controlled HTTP fixture file is invalid: {str(exc) or exc.__class__.__name__}"
        ]
    if digest.lower() != str(fixture.get("sha256") or "").lower():
        return fixture, ["controlled HTTP fixture file changed while it was read"]
    nested = payload.get("http_fixture", payload)
    if not isinstance(nested, Mapping):
        return fixture, ["controlled HTTP fixture JSON must contain an object"]

    effective = dict(nested)
    effective.update(
        {
            key: item
            for key, item in fixture.items()
            if key not in {"exists", "is_file", "error"}
        }
    )
    effective.update(
        {
            "enabled": True,
            "kind": "file",
            "path": snapshot.get("path"),
            "sha256": snapshot.get("sha256"),
            "size": snapshot.get("size"),
        }
    )
    return _prune(effective), []


def _http_fixture_values(fixture: Mapping[str, Any], name: str) -> Optional[list[Any]]:
    value = fixture.get(name)
    if value is None:
        return None
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return [value]


def _http_fixture_errors(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["controlled HTTP fixture must be a mapping, path, or default fixture"]
    fixture, errors = _resolved_http_fixture(value)
    errors = list(errors)
    if fixture.get("enabled") is not True:
        errors.append("controlled HTTP fixture must be explicitly enabled")
    kind = str(fixture.get("kind") or "")
    if kind not in {"capture_artifact", "explicit", "file"}:
        errors.append("controlled HTTP fixture kind is invalid")
    if str(fixture.get("match_mode") or "exact").lower() != "exact":
        errors.append("controlled HTTP fixture supports only exact match mode")

    expected_count = fixture.get("expected_transaction_count")
    if expected_count is not None and (
        not isinstance(expected_count, int)
        or isinstance(expected_count, bool)
        or not 1 <= expected_count <= _MAX_REQUEST_RESPONSE_PAIRS
    ):
        errors.append("HTTP fixture expected_transaction_count is invalid")

    status_values = _http_fixture_values(fixture, "expected_status_codes")
    if status_values is not None:
        if not status_values or len(status_values) > _MAX_REQUEST_RESPONSE_PAIRS:
            errors.append("HTTP fixture expected_status_codes is invalid")
        elif any(
            not isinstance(item, int)
            or isinstance(item, bool)
            or not 100 <= item <= 999
            for item in status_values
        ):
            errors.append("HTTP fixture expected_status_codes is invalid")

    hash_fields = (
        "expected_request_wire_sha256",
        "expected_request_header_sha256",
        "expected_request_body_sha256",
        "expected_response_wire_sha256",
        "expected_response_header_sha256",
        "expected_response_body_sha256",
    )
    for name in hash_fields:
        values = _http_fixture_values(fixture, name)
        if values is None:
            continue
        if (
            not values
            or len(values) > _MAX_REQUEST_RESPONSE_PAIRS
            or any(
                not re.fullmatch(r"[0-9a-fA-F]{64}", str(item or ""))
                for item in values
            )
        ):
            errors.append(f"HTTP fixture {name} is invalid")

    endpoint = fixture.get("endpoint")
    if endpoint is not None:
        if not isinstance(endpoint, Mapping):
            errors.append("HTTP fixture endpoint must be an object")
        else:
            endpoint_ok, endpoint_reason = _validate_endpoint(
                endpoint,
                allow_zero_port=False,
                allow_remote=False,
            )
            if not endpoint_ok:
                errors.append(f"HTTP fixture endpoint is invalid: {endpoint_reason}")
    for name in ("endpoint_identity_sha256", "peer_certificate_sha256"):
        configured = fixture.get(name)
        if configured is not None and not re.fullmatch(
            r"[0-9a-fA-F]{64}", str(configured or "")
        ):
            errors.append(f"HTTP fixture {name} is invalid")
    require_verified_tls = fixture.get("require_verified_tls")
    if require_verified_tls is not None and not isinstance(require_verified_tls, bool):
        errors.append("HTTP fixture require_verified_tls must be a boolean")
    return _deduplicate(errors)


def _http_message_wire(message: Mapping[str, Any]) -> bytes:
    encoded = message.get("payload_base64")
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("HTTP message payload_base64 is missing")
    try:
        wire = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("HTTP message payload_base64 is invalid") from exc
    if not wire:
        raise ValueError("HTTP message wire payload is empty")
    for name in ("wire_length", "length"):
        value = message.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value != len(wire):
            raise ValueError(f"HTTP message {name} does not match its wire payload")
    digest = hashlib.sha256(wire).hexdigest()
    for name in ("wire_sha256", "sha256"):
        value = str(message.get(name) or "").lower()
        if value != digest:
            raise ValueError(f"HTTP message {name} does not match its wire payload")
    return wire


def _http_source_message_errors(
    message: Mapping[str, Any],
    *,
    kind: str,
    limits: Mapping[str, Any],
    request_method: str = "",
) -> list[str]:
    errors: list[str] = []
    try:
        wire = _http_message_wire(message)
        parsed, end = _parse_http1_message(
            wire,
            0,
            kind=kind,
            request_method=request_method,
            limits=limits,
            stream_closed=True,
        )
        if end != len(wire):
            errors.append("HTTP source message contains bytes after its framing boundary")
    except _HttpNeedMoreData as exc:
        return [f"HTTP source message is truncated: {exc}"]
    except ValueError as exc:
        return [f"HTTP source message is invalid: {exc}"]

    simple_fields = [
        "kind",
        "protocol",
        "http_version",
        "start_line",
        "direction",
        "wire_length",
        "wire_sha256",
        "length",
        "sha256",
        "headers_sha256",
        "normalized_headers_sha256",
        "body_length",
        "body_sha256",
        "body_wire_sha256",
    ]
    if kind == "request":
        simple_fields.extend(("method", "request_target"))
    else:
        simple_fields.extend(("status_code", "reason", "request_method"))
    for name in simple_fields:
        if message.get(name) != parsed.get(name):
            errors.append(f"HTTP source message {name} evidence does not match wire bytes")
    for name in ("headers", "trailers", "header_evidence", "body", "framing"):
        expected = message.get(name, [] if name in {"headers", "trailers"} else {})
        actual = parsed.get(name, [] if name in {"headers", "trailers"} else {})
        if expected != actual:
            errors.append(f"HTTP source message {name} evidence does not match wire bytes")

    integrity = _mapping(message.get("source_integrity"))
    if integrity.get("complete") is not True:
        errors.append("HTTP source message is not marked complete")
    if integrity.get("payload_truncated") is not False:
        errors.append("HTTP source message came from truncated evidence")
    if int(integrity.get("reassembly_gap_count") or 0) != 0:
        errors.append("HTTP source message contains a reassembly gap")
    if integrity.get("damaged") is not False:
        errors.append("HTTP source message is marked damaged")
    return _deduplicate(errors)


def _http_source_connection_errors(connection: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if not _capture_connection_has_real_loopback_identity(connection):
        errors.append("HTTP source connection lacks real loopback socket identity")
        return errors
    upstream = _mapping(connection.get("upstream"))
    upstream_identity = _endpoint_identity(upstream)
    socket_identity = _mapping(connection.get("upstream_socket_identity"))
    peer_identity = _mapping(socket_identity.get("peer"))
    if (
        peer_identity.get("host") != upstream_identity.get("host")
        or peer_identity.get("port") != upstream_identity.get("port")
    ):
        errors.append("HTTP source upstream socket does not match its endpoint identity")
    tls = _mapping(connection.get("tls"))
    if tls.get("enabled"):
        certificate_hash = str(tls.get("peer_certificate_sha256") or "")
        certificate = _mapping(tls.get("peer_certificate"))
        endpoint = _mapping(tls.get("endpoint_identity"))
        if not re.fullmatch(r"[0-9a-f]{64}", certificate_hash):
            errors.append("HTTP TLS source connection has no valid certificate hash")
        if certificate.get("presented") is not True:
            errors.append("HTTP TLS source connection has no presented certificate")
        if str(certificate.get("sha256") or "") != certificate_hash:
            errors.append("HTTP TLS source certificate identity is inconsistent")
        if str(endpoint.get("certificate_sha256") or "") != certificate_hash:
            errors.append("HTTP TLS endpoint certificate identity is inconsistent")
        if tls.get("verify") and endpoint.get("certificate_verified") is not True:
            errors.append("HTTP TLS source certificate verification evidence is incomplete")
    return _deduplicate(errors)


def _http_replay_transactions(
    payload: Mapping[str, Any],
    limits: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    transactions: list[dict[str, Any]] = []
    if payload.get("schema_version") != _SCHEMA_VERSION:
        errors.append("HTTP replay source schema_version is unsupported")
    if payload.get("action") != _HTTP_CAPTURE:
        errors.append("HTTP replay source must come from loopback_http_capture")
    if payload.get("provider") != ProtocolRuntimeProvider.provider_name:
        errors.append("HTTP replay source was not produced by the real protocol runtime")
    if payload.get("status") != "ok":
        errors.append("HTTP replay source capture did not complete successfully")

    report = _mapping(payload.get("report_section"))
    after = _mapping(payload.get("after_snapshot")) or _mapping(
        report.get("after_snapshot")
    )
    integrity = _mapping(after.get("integrity"))
    if after.get("application_protocol") != "http/1.1":
        errors.append("HTTP replay source is not HTTP/1.1 evidence")
    if after.get("capture_kind") != "real_loopback_http_proxy":
        errors.append("HTTP replay source is not a real loopback HTTP capture")
    if after.get("real_socket_evidence") is not True:
        errors.append("HTTP replay source lacks real socket evidence")
    if after.get("real_capture_success") is not True:
        errors.append("HTTP replay source is not marked as a real capture success")
    if after.get("allow_remote") is not False:
        errors.append("HTTP replay source was not restricted to loopback endpoints")
    if integrity.get("complete") is not True or integrity.get("fail_closed") is not False:
        errors.append("HTTP replay source integrity is incomplete")
    if integrity.get("truncated") is not False:
        errors.append("HTTP replay source is truncated")
    if int(integrity.get("gap_count") or 0) != 0:
        errors.append("HTTP replay source contains a reassembly or correlation gap")
    if integrity.get("tampered") is not False or integrity.get("damaged") is not False:
        errors.append("HTTP replay source is marked tampered or damaged")

    try:
        raw_messages = _artifact_sequence(payload, "messages")
        raw_pairs = _artifact_sequence(payload, "request_response_pairs")
        raw_connections = _artifact_sequence(payload, "connections")
        raw_frames = _artifact_sequence(payload, "frames")
        raw_tunnels = _artifact_sequence(payload, "connect_tunnels")
    except ValueError as exc:
        return [], _deduplicate([*errors, str(exc)])
    if not raw_messages:
        errors.append("HTTP replay source contains no messages")
    if not raw_pairs:
        errors.append("HTTP replay source contains no request-response pairs")
    if not raw_connections:
        errors.append("HTTP replay source contains no connection evidence")
    if not raw_frames:
        errors.append("HTTP replay source contains no frame evidence")
    else:
        frame_objects = [dict(item) for item in raw_frames if isinstance(item, Mapping)]
        if len(frame_objects) != len(raw_frames):
            errors.append("HTTP replay source contains a non-object frame")
        else:
            errors.extend(
                _replay_frame_errors(
                    frame_objects,
                    limits,
                    replay_mode="session",
                )
            )
            for index, frame in enumerate(frame_objects, start=1):
                if frame.get("sequence") != index:
                    errors.append(f"HTTP source frame {index} has a sequence gap")
                if str(frame.get("transport") or "tcp").lower() != "tcp":
                    errors.append(f"HTTP source frame {index} is not TCP evidence")

    messages: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw_messages, start=1):
        if not isinstance(item, Mapping):
            errors.append(f"HTTP source message {index} is not an object")
            continue
        message = dict(item)
        message_id = str(message.get("id") or "")
        if not message_id:
            errors.append(f"HTTP source message {index} has no id")
            continue
        if message_id in messages:
            errors.append(f"HTTP source message id {message_id!r} is duplicated")
            continue
        if message.get("sequence") != index:
            errors.append(f"HTTP source message {message_id!r} has a sequence gap")
        messages[message_id] = message

    connections: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw_connections, start=1):
        if not isinstance(item, Mapping):
            errors.append(f"HTTP source connection {index} is not an object")
            continue
        connection = dict(item)
        connection_id = str(connection.get("connection_id") or "")
        if not connection_id or connection_id in connections:
            errors.append(f"HTTP source connection {index} has an invalid identity")
            continue
        connections[connection_id] = connection

    tunnels_by_connection: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw_tunnels, start=1):
        if not isinstance(item, Mapping):
            errors.append(f"HTTP source CONNECT tunnel {index} is not an object")
            continue
        tunnel = dict(item)
        connection_id = str(tunnel.get("connection_id") or "")
        if not connection_id or connection_id in tunnels_by_connection:
            errors.append(f"HTTP source CONNECT tunnel {index} has an invalid identity")
            continue
        if tunnel.get("sequence") != index:
            errors.append(f"HTTP source CONNECT tunnel {index} has a sequence gap")
        tunnels_by_connection[connection_id] = tunnel

    accounted_message_ids: set[str] = set()
    total_wire_bytes = 0
    required_frames = 0
    for index, item in enumerate(raw_pairs, start=1):
        if not isinstance(item, Mapping):
            errors.append(f"HTTP source transaction {index} is not an object")
            continue
        pair = dict(item)
        if pair.get("sequence") != index:
            errors.append(f"HTTP source transaction {index} has a sequence gap")
        if pair.get("complete") is not True:
            errors.append(f"HTTP source transaction {index} is incomplete")
        request_id = str(pair.get("request_message_id") or "")
        response_id = str(pair.get("response_message_id") or "")
        interim_ids_value = pair.get("interim_response_message_ids") or []
        if not isinstance(interim_ids_value, Sequence) or isinstance(
            interim_ids_value, (str, bytes, bytearray)
        ):
            errors.append(f"HTTP source transaction {index} interim ids are invalid")
            interim_ids: list[str] = []
        else:
            interim_ids = [str(value or "") for value in interim_ids_value]
        request = messages.get(request_id, {})
        response = messages.get(response_id, {})
        interim_responses = [messages.get(message_id, {}) for message_id in interim_ids]
        if not request or request.get("kind") != "http_request":
            errors.append(f"HTTP source transaction {index} has no valid request message")
            continue
        if not response or response.get("kind") != "http_response":
            errors.append(f"HTTP source transaction {index} has no valid final response")
            continue
        if any(not value or value.get("kind") != "http_response" for value in interim_responses):
            errors.append(f"HTTP source transaction {index} has an invalid interim response")
            continue
        if any(
            not 100 <= int(value.get("status_code") or 0) < 200
            or int(value.get("status_code") or 0) == 101
            for value in interim_responses
        ):
            errors.append(f"HTTP source transaction {index} interim status is invalid")
        connection_id = str(pair.get("connection_id") or "")
        if (
            str(request.get("connection_id") or "") != connection_id
            or str(response.get("connection_id") or "") != connection_id
            or any(
                str(value.get("connection_id") or "") != connection_id
                for value in interim_responses
            )
        ):
            errors.append(f"HTTP source transaction {index} connection identity is inconsistent")
        connection = connections.get(connection_id, {})
        if not connection:
            errors.append(f"HTTP source transaction {index} has no connection evidence")
        else:
            errors.extend(
                f"transaction {index}: {error}"
                for error in _http_source_connection_errors(connection)
            )

        request_method = str(request.get("method") or "")
        errors.extend(
            f"transaction {index} request: {error}"
            for error in _http_source_message_errors(
                request,
                kind="request",
                limits=limits,
            )
        )
        for interim_index, interim in enumerate(interim_responses, start=1):
            errors.extend(
                f"transaction {index} interim response {interim_index}: {error}"
                for error in _http_source_message_errors(
                    interim,
                    kind="response",
                    limits=limits,
                    request_method=request_method,
                )
            )
        errors.extend(
            f"transaction {index} response: {error}"
            for error in _http_source_message_errors(
                response,
                kind="response",
                limits=limits,
                request_method=request_method,
            )
        )

        pair_evidence = {
            "method": request.get("method"),
            "request_target": request.get("request_target"),
            "status_code": response.get("status_code"),
            "request_wire_sha256": request.get("wire_sha256"),
            "request_header_sha256": request.get("headers_sha256"),
            "request_body_sha256": request.get("body_sha256"),
            "response_wire_sha256": response.get("wire_sha256"),
            "response_header_sha256": response.get("headers_sha256"),
            "response_body_sha256": response.get("body_sha256"),
        }
        for name, expected in pair_evidence.items():
            if pair.get(name) != expected:
                errors.append(
                    f"HTTP source transaction {index} {name} does not match its messages"
                )

        transaction_limitations = _deduplicate(
            [
                *list(pair.get("limitations") or []),
                *_http_transaction_limitations(request, response),
            ]
        )
        if interim_responses:
            transaction_limitations.append(
                "informational response sequencing is not generalized"
            )
        replay_supported = bool(pair.get("replay_supported")) and not interim_responses
        if _http_transaction_limitations(request, response):
            replay_supported = False
        connect_tunnel: dict[str, Any] = {}
        connect_frames: list[dict[str, Any]] = []
        connect_half_close_events: list[dict[str, Any]] = []
        if request_method.upper() == "CONNECT":
            connect_tunnel = tunnels_by_connection.pop(connection_id, {})
            status_code = int(response.get("status_code") or 0)
            if not 200 <= status_code < 300:
                errors.append(
                    f"HTTP source transaction {index} CONNECT response is not successful"
                )
            if not connect_tunnel:
                errors.append(
                    f"HTTP source transaction {index} has no CONNECT tunnel evidence"
                )
            else:
                authority = str(request.get("request_target") or "")
                if str(connect_tunnel.get("authority") or "") != authority:
                    errors.append(
                        f"HTTP source transaction {index} CONNECT authority drifted"
                    )
                if int(connect_tunnel.get("status_code") or 0) != status_code:
                    errors.append(
                        f"HTTP source transaction {index} CONNECT status is inconsistent"
                    )
                if connect_tunnel.get("established") is not True:
                    errors.append(
                        f"HTTP source transaction {index} CONNECT tunnel is not established"
                    )
                authority_endpoint, authority_errors = _connect_authority_endpoint(
                    authority
                )
                if _mapping(connect_tunnel.get("authority_endpoint")) != authority_endpoint:
                    authority_errors.append(
                        "CONNECT authority endpoint evidence does not match"
                    )
                if _mapping(
                    connect_tunnel.get("authority_endpoint_identity")
                ) != _endpoint_identity(authority_endpoint):
                    authority_errors.append(
                        "CONNECT authority endpoint identity does not match"
                    )
                errors.extend(
                    f"transaction {index}: {error}" for error in authority_errors
                )
                client_payload, client_errors = _opaque_tunnel_payload(
                    connect_tunnel.get("client_to_server"),
                    direction="client_to_server",
                )
                server_payload, server_errors = _opaque_tunnel_payload(
                    connect_tunnel.get("server_to_client"),
                    direction="server_to_client",
                )
                errors.extend(
                    f"transaction {index}: {error}"
                    for error in [*client_errors, *server_errors]
                )
                try:
                    request_wire = _http_message_wire(request)
                    response_wire = _http_message_wire(response)
                except ValueError:
                    request_wire = b""
                    response_wire = b""
                connect_frames, connect_frame_errors = _connect_tunnel_source_frames(
                    [dict(item) for item in raw_frames if isinstance(item, Mapping)],
                    connection_id=connection_id,
                    request_wire=request_wire,
                    response_wire=response_wire,
                    client_payload=client_payload,
                    server_payload=server_payload,
                )
                errors.extend(
                    f"transaction {index}: {error}" for error in connect_frame_errors
                )
                transcript_errors = _connect_transcript_errors(
                    connect_tunnel.get("transcript"),
                    tunnel_frames=connect_frames,
                )
                connect_half_close_events, half_close_errors = _connect_half_close_events(
                    connect_tunnel.get("half_close_events"),
                    tunnel_frames=connect_frames,
                )
                errors.extend(
                    f"transaction {index}: {error}"
                    for error in [*transcript_errors, *half_close_errors]
                )
                if not client_payload or not server_payload:
                    errors.append(
                        f"HTTP source transaction {index} CONNECT tunnel is not bidirectional"
                    )
                replay_supported = (
                    200 <= status_code < 300
                    and not interim_responses
                    and not authority_errors
                    and not client_errors
                    and not server_errors
                    and not connect_frame_errors
                    and not transcript_errors
                    and not half_close_errors
                    and bool(client_payload)
                    and bool(server_payload)
                )
        transactions.append(
            {
                "sequence": index,
                "connection_id": connection_id,
                "pair": pair,
                "request": request,
                "response": response,
                "interim_responses": interim_responses,
                "source_connection": connection,
                "connect_tunnel": connect_tunnel,
                "connect_tunnel_frames": connect_frames,
                "connect_half_close_events": connect_half_close_events,
                "replay_supported": replay_supported,
                "limitations": _deduplicate(transaction_limitations),
            }
        )
        linked_ids = [request_id, *interim_ids, response_id]
        for message_id in linked_ids:
            if message_id in accounted_message_ids:
                errors.append(
                    f"HTTP source message {message_id!r} is linked to multiple transactions"
                )
            accounted_message_ids.add(message_id)
        try:
            transaction_wires = [
                _http_message_wire(request),
                *[_http_message_wire(value) for value in interim_responses],
                _http_message_wire(response),
            ]
        except ValueError:
            transaction_wires = []
        total_wire_bytes += sum(len(value) for value in transaction_wires)
        required_frames += 1 + len(interim_responses) + 1
        if connect_frames:
            total_wire_bytes += sum(
                int(frame.get("length") or 0) for frame in connect_frames
            )
            required_frames += len(connect_frames)

    unlinked = set(messages) - accounted_message_ids
    if unlinked:
        errors.append("HTTP replay source contains uncorrelated HTTP messages")
    if tunnels_by_connection:
        errors.append("HTTP replay source contains uncorrelated CONNECT tunnel evidence")
    if int(after.get("message_count") or -1) != len(raw_messages):
        errors.append("HTTP replay source message_count is inconsistent")
    if int(after.get("request_response_pair_count") or -1) != len(raw_pairs):
        errors.append("HTTP replay source transaction count is inconsistent")
    if int(after.get("connection_count") or -1) != len(raw_connections):
        errors.append("HTTP replay source connection_count is inconsistent")

    if len(raw_messages) > int(limits.get("max_messages") or 0):
        errors.append("HTTP replay source exceeds max_messages")
    if len(raw_messages) > int(limits.get("max_correlation_messages") or 0):
        errors.append("HTTP replay source exceeds max_correlation_messages")
    if len(raw_pairs) > int(limits.get("max_request_response_pairs") or 0):
        errors.append("HTTP replay source exceeds max_request_response_pairs")
    if len(transactions) > int(limits.get("max_connections") or 0):
        errors.append("HTTP fixture replay requires more than max_connections")
    if max(required_frames, len(raw_frames)) > int(limits.get("max_frames") or 0):
        errors.append("HTTP fixture replay requires more than max_frames")
    if total_wire_bytes > int(limits.get("max_bytes") or 0):
        errors.append("HTTP fixture replay source bytes exceed max_bytes")
    return transactions, _deduplicate(errors)


def _http_expected_values_errors(
    fixture: Mapping[str, Any],
    *,
    name: str,
    actual: Sequence[Any],
) -> list[str]:
    configured = _http_fixture_values(fixture, name)
    if configured is None:
        return []
    expected = [str(value).lower() for value in configured]
    observed = [str(value).lower() for value in actual]
    if expected != observed:
        return [f"HTTP fixture {name} does not match the replay source"]
    return []


def _verify_http_fixture_source(
    value: Any,
    transactions: Sequence[Mapping[str, Any]],
    destination: Mapping[str, Any],
) -> list[str]:
    errors = _http_fixture_errors(value)
    fixture, resolution_errors = _resolved_http_fixture(value)
    errors.extend(resolution_errors)
    endpoint_ok, endpoint_reason = _validate_endpoint(
        destination,
        allow_zero_port=False,
        allow_remote=False,
    )
    if not endpoint_ok:
        errors.append(f"controlled HTTP destination is invalid: {endpoint_reason}")
    expected_count = fixture.get("expected_transaction_count")
    if expected_count is not None and int(expected_count) != len(transactions):
        errors.append("HTTP fixture transaction count does not match the replay source")
    configured_endpoint = _mapping(fixture.get("endpoint"))
    if configured_endpoint and endpoint_ok:
        if _endpoint_key(configured_endpoint) != _endpoint_key(destination):
            errors.append("HTTP fixture endpoint does not match the planned destination")
    configured_identity = str(fixture.get("endpoint_identity_sha256") or "").lower()
    if configured_identity and configured_identity != str(
        _endpoint_identity(destination).get("identity_sha256") or ""
    ).lower():
        errors.append("HTTP fixture endpoint identity hash does not match the destination")

    requests = [_mapping(item.get("request")) for item in transactions]
    responses = [_mapping(item.get("response")) for item in transactions]
    expected_fields = {
        "expected_status_codes": [item.get("status_code") for item in responses],
        "expected_request_wire_sha256": [item.get("wire_sha256") for item in requests],
        "expected_request_header_sha256": [
            item.get("headers_sha256") for item in requests
        ],
        "expected_request_body_sha256": [item.get("body_sha256") for item in requests],
        "expected_response_wire_sha256": [
            item.get("wire_sha256") for item in responses
        ],
        "expected_response_header_sha256": [
            item.get("headers_sha256") for item in responses
        ],
        "expected_response_body_sha256": [
            item.get("body_sha256") for item in responses
        ],
    }
    for name, actual in expected_fields.items():
        errors.extend(
            _http_expected_values_errors(
                fixture,
                name=name,
                actual=actual,
            )
        )
    return _deduplicate(errors)


def _http_replay_limitations(
    transactions: Sequence[Mapping[str, Any]],
) -> list[str]:
    limitations: list[str] = []
    by_connection: dict[str, int] = {}
    for transaction in transactions:
        limitations.extend(str(value) for value in transaction.get("limitations", []))
        connection_id = str(transaction.get("connection_id") or "")
        by_connection[connection_id] = by_connection.get(connection_id, 0) + 1
    if any(count > 1 for count in by_connection.values()):
        limitations.append(
            "persistent multi-transaction connection replay is not generalized; "
            "transactions use fresh controlled connections"
        )
    return _deduplicate(limitations)


def _verify_http_fixture_connection(
    value: Any,
    socket_identity: Mapping[str, Any],
    tls_evidence: Mapping[str, Any],
    *,
    transaction: Optional[Mapping[str, Any]] = None,
) -> list[str]:
    fixture, errors = _resolved_http_fixture(value)
    errors = list(errors)
    if not _socket_identity_is_real_loopback(socket_identity):
        errors.append("controlled HTTP fixture did not use a real loopback socket")
    peer = _mapping(socket_identity.get("peer"))
    configured_endpoint = _mapping(fixture.get("endpoint"))
    if configured_endpoint and (
        peer.get("host") != _endpoint_identity(configured_endpoint).get("host")
        or peer.get("port") != configured_endpoint.get("port")
    ):
        errors.append("controlled HTTP fixture peer endpoint identity did not match")
    configured_identity = str(fixture.get("endpoint_identity_sha256") or "").lower()
    if configured_identity and configured_identity != str(
        peer.get("identity_sha256") or ""
    ).lower():
        errors.append("controlled HTTP fixture peer endpoint hash did not match")

    expected_certificate = str(fixture.get("peer_certificate_sha256") or "").lower()
    require_verified_tls = fixture.get("require_verified_tls") is True
    source_connection = _mapping(_mapping(transaction).get("source_connection"))
    source_tls = _mapping(source_connection.get("tls"))
    if str(fixture.get("kind") or "") == "capture_artifact":
        if bool(source_tls.get("enabled")) != bool(tls_evidence.get("enabled")):
            errors.append("controlled HTTP fixture TLS mode differs from the source capture")
        if source_tls.get("enabled"):
            expected_certificate = str(
                source_tls.get("peer_certificate_sha256") or ""
            ).lower()
            require_verified_tls = bool(source_tls.get("verify"))

    actual_certificate = str(tls_evidence.get("peer_certificate_sha256") or "").lower()
    if expected_certificate and actual_certificate != expected_certificate:
        errors.append("controlled HTTP fixture certificate identity did not match")
    if require_verified_tls:
        endpoint_identity = _mapping(tls_evidence.get("endpoint_identity"))
        if not tls_evidence.get("enabled") or not tls_evidence.get("verify"):
            errors.append("controlled HTTP fixture requires verified TLS")
        if endpoint_identity.get("certificate_verified") is not True:
            errors.append("controlled HTTP fixture TLS certificate was not verified")
    return _deduplicate(errors)


def _receive_http1_responses(
    value: socket.socket,
    *,
    request_method: str,
    limits: Mapping[str, Any],
    deadline: float,
    timeout_ms: int,
    byte_budget: int,
    response_frame_budget: int,
) -> tuple[list[dict[str, Any]], bytearray]:
    if byte_budget <= 0:
        raise ValueError("HTTP response has no remaining byte budget")
    if response_frame_budget <= 0:
        raise ValueError("HTTP response has no remaining frame budget")
    stream_budget = min(
        byte_budget,
        int(limits.get("max_stream_bytes") or 0),
    )
    buffer = bytearray()
    offset = 0
    responses: list[dict[str, Any]] = []
    stream_closed = False
    response_limit = min(
        response_frame_budget,
        int(limits.get("max_messages") or 0),
    )

    while True:
        if len(responses) >= response_limit:
            raise ValueError("HTTP response sequence exceeds the message/frame budget")
        try:
            response, end = _parse_http1_message(
                bytes(buffer),
                offset,
                kind="response",
                request_method=request_method,
                limits=limits,
                stream_closed=stream_closed,
            )
        except _HttpNeedMoreData as exc:
            if stream_closed:
                raise ValueError(f"controlled fixture response is truncated: {exc}") from exc
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise RuntimeError("controlled fixture response exceeded duration_ms")
            remaining_bytes = stream_budget - len(buffer)
            if remaining_bytes <= 0:
                raise ValueError("controlled fixture response exhausted its byte budget")
            value.settimeout(min(timeout_ms / 1_000.0, remaining_time))
            try:
                chunk = value.recv(min(_RECV_BYTES, remaining_bytes))
            except socket.timeout as timeout_error:
                raise RuntimeError("controlled fixture response timed out") from timeout_error
            if chunk:
                buffer.extend(chunk)
            else:
                stream_closed = True
            continue
        except ValueError:
            raise

        responses.append(response)
        offset = end
        status_code = int(response.get("status_code") or 0)
        informational = 100 <= status_code < 200 and status_code != 101
        if informational:
            continue
        is_connect_tunnel = (
            str(request_method or "").upper() == "CONNECT"
            and 200 <= status_code < 300
        )
        if offset != len(buffer) and not is_connect_tunnel:
            raise ValueError(
                "controlled fixture returned trailing bytes after the final HTTP response"
            )
        return responses, bytearray(buffer[offset:])


def _http_response_match_errors(
    expected: Mapping[str, Any],
    actual: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    try:
        expected_wire = _http_message_wire(expected)
        actual_wire = _http_message_wire(actual)
        if expected_wire != actual_wire:
            errors.append("controlled fixture response wire bytes did not match the capture")
    except ValueError as exc:
        errors.append(str(exc))
    comparisons = (
        ("status_code", "status code"),
        ("start_line", "status line"),
        ("headers_sha256", "header hash"),
        ("normalized_headers_sha256", "normalized header hash"),
        ("body_sha256", "body hash"),
        ("body_wire_sha256", "body wire hash"),
        ("wire_sha256", "wire hash"),
        ("wire_length", "wire length"),
        ("body_length", "body length"),
    )
    for name, label in comparisons:
        if expected.get(name) != actual.get(name):
            errors.append(f"controlled fixture response {label} did not match")
    if _mapping(expected.get("framing")) != _mapping(actual.get("framing")):
        errors.append("controlled fixture response framing did not match")
    if list(expected.get("headers") or []) != list(actual.get("headers") or []):
        errors.append("controlled fixture response headers did not match")
    if list(expected.get("trailers") or []) != list(actual.get("trailers") or []):
        errors.append("controlled fixture response trailers did not match")
    return _deduplicate(errors)


def _verify_http_fixture_response(
    value: Any,
    *,
    index: int,
    actual: Mapping[str, Any],
) -> list[str]:
    fixture, errors = _resolved_http_fixture(value)
    errors = list(errors)
    fields = {
        "expected_status_codes": actual.get("status_code"),
        "expected_response_wire_sha256": actual.get("wire_sha256"),
        "expected_response_header_sha256": actual.get("headers_sha256"),
        "expected_response_body_sha256": actual.get("body_sha256"),
    }
    for name, observed in fields.items():
        expected = _http_fixture_values(fixture, name)
        if expected is None:
            continue
        if index < 1 or index > len(expected):
            errors.append(f"HTTP fixture {name} has no value for transaction {index}")
            continue
        if str(expected[index - 1]).lower() != str(observed).lower():
            errors.append(f"HTTP fixture {name} did not match transaction {index}")
    return _deduplicate(errors)


def _select_replay_frames(
    payload: Mapping[str, Any],
    direction: str,
    *,
    transport: str = "tcp",
    replay_mode: str = "frames",
) -> list[dict[str, Any]]:
    if replay_mode not in _REPLAY_MODES:
        raise ValueError("replay_mode must be frames or session")
    if replay_mode == "frames" and direction not in _DIRECTIONS:
        raise ValueError("frame_direction must be client_to_server or server_to_client")
    if transport not in {"tcp", "udp", "raw", "named_pipe"}:
        raise ValueError("transport must be tcp, udp, raw, or named_pipe")
    raw_frames = _artifact_sequence(payload, "frames")
    if not raw_frames:
        raw_messages = _artifact_sequence(payload, "messages")
        if not raw_messages:
            raise ValueError("capture artifact does not contain a frame or message sequence")
        raw_frames = _messages_to_replay_frames(raw_messages)
    selected: list[dict[str, Any]] = []
    for item in raw_frames:
        if not isinstance(item, Mapping):
            raise ValueError("capture artifact contains a non-object frame")
        frame = dict(item)
        frame_transport = str(frame.get("transport") or "tcp").lower()
        frame_direction = str(frame.get("direction") or "")
        direction_selected = (
            frame_direction in _DIRECTIONS
            if replay_mode == "session"
            else frame_direction == direction
        )
        if direction_selected and frame_transport == transport:
            selected.append(frame)
    if not selected:
        selection = "session" if replay_mode == "session" else direction
        raise ValueError(f"capture artifact has no {transport} {selection} frames")
    return selected


def _artifact_sequence(payload: Mapping[str, Any], name: str) -> list[Any]:
    report = _mapping(payload.get("report_section"))
    containers = (
        payload,
        _mapping(payload.get("after_snapshot")),
        report,
        _mapping(report.get("after_snapshot")),
    )
    for container in containers:
        if name not in container:
            continue
        value = container.get(name)
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise ValueError(f"capture artifact {name} must be a sequence")
        if value:
            return list(value)
    return []


def _replay_source_connection_map(
    payload: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(_artifact_sequence(payload, "connections"), start=1):
        if not isinstance(item, Mapping):
            raise ValueError(f"capture artifact connection {index} is not an object")
        connection = dict(item)
        connection_id = str(connection.get("connection_id") or "")
        if not connection_id:
            raise ValueError(f"capture artifact connection {index} has no identity")
        if connection_id in result:
            raise ValueError(
                f"capture artifact connection identity {connection_id!r} is duplicated"
            )
        result[connection_id] = connection
    return result


def _source_tls_identity_errors(tls: Mapping[str, Any]) -> list[str]:
    if not tls.get("enabled"):
        return []
    errors: list[str] = []
    certificate_hash = str(tls.get("peer_certificate_sha256") or "").lower()
    certificate = _mapping(tls.get("peer_certificate"))
    endpoint = _mapping(tls.get("endpoint_identity"))
    if not re.fullmatch(r"[0-9a-f]{64}", certificate_hash):
        errors.append("TLS replay source has no valid peer certificate hash")
    if certificate.get("presented") is not True:
        errors.append("TLS replay source has no presented peer certificate")
    if str(certificate.get("sha256") or "").lower() != certificate_hash:
        errors.append("TLS replay source certificate identity is inconsistent")
    if str(endpoint.get("certificate_sha256") or "").lower() != certificate_hash:
        errors.append("TLS replay source endpoint certificate identity is inconsistent")
    if tls.get("verify") and endpoint.get("certificate_verified") is not True:
        errors.append("TLS replay source certificate verification evidence is incomplete")
    return _deduplicate(errors)


def _replay_source_tls_errors(
    payload: Mapping[str, Any],
    frames: Sequence[Mapping[str, Any]],
    configured_tls: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    try:
        connections = _replay_source_connection_map(payload)
    except ValueError as exc:
        return [str(exc)]
    source_ids = list(
        dict.fromkeys(str(frame.get("connection_id") or "") for frame in frames)
    )
    provider_capture = (
        payload.get("provider") == ProtocolRuntimeProvider.provider_name
        and payload.get("action") in _CAPTURE_ACTIONS
    )
    if provider_capture and not connections:
        errors.append("protocol runtime capture source lacks connection identity evidence")
    for source_id in source_ids:
        connection = connections.get(source_id)
        if provider_capture and connection is None:
            errors.append(
                f"protocol runtime capture source connection {source_id!r} has no evidence"
            )
            continue
        source_tls = _mapping(_mapping(connection).get("tls"))
        if not source_tls.get("enabled"):
            continue
        errors.extend(
            f"source connection {source_id!r}: {error}"
            for error in _source_tls_identity_errors(source_tls)
        )
        if configured_tls.get("enabled") is not True:
            errors.append(
                f"source connection {source_id!r} was captured over TLS; replay TLS is required"
            )
        if source_tls.get("verify") and configured_tls.get("verify") is not True:
            errors.append(
                f"source connection {source_id!r} used verified TLS; replay must also verify TLS"
            )
    return _deduplicate(errors)


def _replay_tls_identity_binding(
    source_connection: Any,
    tls_evidence: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    source_tls = _mapping(_mapping(source_connection).get("tls"))
    source_tls_enabled = source_tls.get("enabled") is True
    expected_hash = str(source_tls.get("peer_certificate_sha256") or "").lower()
    actual_hash = str(tls_evidence.get("peer_certificate_sha256") or "").lower()
    errors = _source_tls_identity_errors(source_tls)
    pin_required = source_tls_enabled
    pin_matched = bool(pin_required and expected_hash and actual_hash == expected_hash)

    if source_tls_enabled:
        if tls_evidence.get("enabled") is not True:
            errors.append("TLS replay source requires a TLS destination connection")
        if not pin_matched:
            errors.append("TLS replay peer certificate does not match the source capture")
        if source_tls.get("verify"):
            endpoint = _mapping(tls_evidence.get("endpoint_identity"))
            if (
                tls_evidence.get("verify") is not True
                or endpoint.get("certificate_verified") is not True
            ):
                errors.append(
                    "TLS replay did not preserve source certificate verification"
                )

    errors = _deduplicate(errors)
    if pin_required:
        identity_basis = "source_certificate_pin_and_configured_ca_hostname"
    elif tls_evidence.get("verify"):
        identity_basis = "configured_ca_and_hostname"
    elif tls_evidence.get("enabled"):
        identity_basis = "unverified_tls_no_source_pin"
    else:
        identity_basis = "plaintext_socket_peer"
    binding = _prune(
        {
            "source_connection_evidence": bool(source_connection),
            "source_tls_enabled": source_tls_enabled,
            "certificate_pin_required": pin_required,
            "expected_peer_certificate_sha256": expected_hash if pin_required else None,
            "actual_peer_certificate_sha256": actual_hash if tls_evidence.get("enabled") else None,
            "certificate_pin_matched": pin_matched if pin_required else None,
            "certificate_identity_basis": identity_basis,
            "identity_check_completed": not errors,
            "application_data_release": (
                "allowed_after_identity_check" if not errors else "blocked"
            ),
        }
    )
    return binding, errors


def _messages_to_replay_frames(messages: Sequence[Any]) -> list[dict[str, Any]]:
    timestamps = [
        _float_value(item.get("timestamp_start"), -1.0)
        for item in messages
        if isinstance(item, Mapping)
    ]
    valid_timestamps = [value for value in timestamps if value >= 0.0]
    timestamp_base = min(valid_timestamps) if valid_timestamps else None
    frames: list[dict[str, Any]] = []
    for index, item in enumerate(messages, start=1):
        if not isinstance(item, Mapping):
            raise ValueError("capture artifact contains a non-object message")
        message = dict(item)
        try:
            data = _imported_message_payload(message)
        except ValueError as exc:
            raise ValueError(f"message {index}: {exc}") from exc
        message_transport = str(message.get("transport") or "raw").strip().lower()
        message_direction = _replay_direction(message.get("direction"))
        metadata = _mapping(message.get("metadata"))
        timestamp = _float_value(message.get("timestamp_start"), -1.0)
        elapsed_ms = (
            max(0.0, (timestamp - timestamp_base) * 1_000.0)
            if timestamp_base is not None and timestamp >= 0.0
            else 0.0
        )
        source_hash = str(
            message.get("sha256") or message.get("payload_sha256") or ""
        ).lower()
        if source_hash and source_hash != hashlib.sha256(data).hexdigest():
            raise ValueError(f"message {index} payload hash does not match")
        frames.append(
            _prune(
                {
                    "sequence": index,
                    "connection_id": str(
                        message.get("flow_id")
                        or message.get("connection_id")
                        or f"imported-flow-{index}"
                    ),
                    "elapsed_ms": round(elapsed_ms, 3),
                    "transport": message_transport,
                    "direction": message_direction,
                    "length": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "payload_base64": base64.b64encode(data).decode("ascii"),
                    "source_sequence": message.get("sequence_start")
                    or message.get("sequence")
                    or message.get("id"),
                    "source_message_id": message.get("id") or message.get("message_id"),
                    "source_kind": "protocol_capture_message",
                    "source_payload_size": message.get("payload_size"),
                    "source_captured_size": message.get("captured_size"),
                    "source_integrity": {
                        "payload_truncated": bool(
                            message.get("payload_truncated")
                            or _mapping(message.get("payload")).get("truncated")
                        ),
                        "reassembly_gap_count": int(
                            metadata.get("reassembly_gap_count") or 0
                        ),
                        "overlap_bytes": int(metadata.get("overlap_bytes") or 0),
                        "damaged": bool(
                            message.get("damaged")
                            or message.get("corrupt")
                            or message.get("malformed")
                            or metadata.get("damaged")
                            or metadata.get("corrupt")
                            or metadata.get("malformed")
                            or message.get("checksum_valid") is False
                            or metadata.get("checksum_valid") is False
                        ),
                    },
                }
            )
        )
    return frames


def _imported_message_payload(message: Mapping[str, Any]) -> bytes:
    nested = _mapping(message.get("payload"))
    encoded_values = [
        value
        for value in (message.get("payload_base64"), nested.get("base64"))
        if value not in (None, "")
    ]
    hex_values = [
        value
        for value in (message.get("payload_hex"), nested.get("hex"))
        if value not in (None, "")
    ]
    decoded: list[bytes] = []
    for value in encoded_values:
        try:
            decoded.append(base64.b64decode(str(value).encode("ascii"), validate=True))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("payload_base64 is invalid") from exc
    for value in hex_values:
        try:
            decoded.append(bytes.fromhex(str(value)))
        except ValueError as exc:
            raise ValueError("payload_hex is invalid") from exc
    if not decoded:
        raise ValueError("payload_hex or payload_base64 is missing")
    if any(value != decoded[0] for value in decoded[1:]):
        raise ValueError("payload encodings disagree")
    return decoded[0]


def _replay_direction(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower().replace("-", "_")
    if normalized in {"client_to_server", "a_to_b", "a2b", "outbound", "send", "request"}:
        return "client_to_server"
    if normalized in {"server_to_client", "b_to_a", "b2a", "inbound", "receive", "recv", "response"}:
        return "server_to_client"
    return "client_to_server"


def _replay_frame_errors(
    frames: Sequence[Mapping[str, Any]],
    limits: Mapping[str, Any],
    *,
    replay_mode: str = "frames",
    offline: bool = False,
) -> list[str]:
    errors: list[str] = []
    if replay_mode == "session" or offline:
        if len(frames) > int(limits.get("max_frames") or 0):
            errors.append("selected frames exceed max_frames")
    elif len(frames) >= int(limits.get("max_frames") or 0):
        errors.append("selected frames leave no bounded capacity for response evidence")
    if len({str(item.get("connection_id") or "") for item in frames}) > int(
        limits.get("max_connections") or 0
    ):
        errors.append("capture connection count exceeds max_connections")
    if len(frames) > int(limits.get("max_messages") or 0):
        errors.append("selected frames exceed max_messages")
    message_byte_limit = min(
        int(limits.get("max_message_bytes") or 0),
        int(limits.get("max_stream_bytes") or 0),
    )
    total = 0
    for index, frame in enumerate(frames):
        connection_id = str(frame.get("connection_id") or "")
        if not connection_id:
            errors.append(f"frame {index} has no connection_id")
        try:
            data = _frame_payload(frame)
        except ValueError as exc:
            errors.append(f"frame {index}: {exc}")
            continue
        total += len(data)
        if len(data) > message_byte_limit:
            errors.append(f"frame {index} exceeds the message/stream byte budget")
        expected_length = frame.get("length")
        if expected_length is not None:
            try:
                if int(expected_length) != len(data):
                    errors.append(f"frame {index} length does not match payload")
            except (TypeError, ValueError, OverflowError):
                errors.append(f"frame {index} length is invalid")
        expected_hash = str(frame.get("sha256") or "")
        if expected_hash and expected_hash.lower() != hashlib.sha256(data).hexdigest():
            errors.append(f"frame {index} sha256 does not match payload")
        captured_size = frame.get("source_captured_size")
        if captured_size is not None:
            try:
                if int(captured_size) != len(data):
                    errors.append(f"frame {index} captured size does not match payload")
            except (TypeError, ValueError, OverflowError):
                errors.append(f"frame {index} captured size is invalid")
        source_size = frame.get("source_payload_size")
        integrity = _mapping(frame.get("source_integrity"))
        if integrity.get("payload_truncated"):
            errors.append(f"frame {index} came from truncated evidence")
        if int(integrity.get("reassembly_gap_count") or 0) > 0:
            errors.append(f"frame {index} contains a TCP reassembly gap")
        if integrity.get("damaged"):
            errors.append(f"frame {index} is marked damaged or malformed")
        if source_size is not None and not integrity.get("payload_truncated"):
            try:
                if int(source_size) != len(data):
                    errors.append(f"frame {index} source size does not match payload")
            except (TypeError, ValueError, OverflowError):
                errors.append(f"frame {index} source size is invalid")
    if (replay_mode == "session" or offline) and total > int(limits.get("max_bytes") or 0):
        errors.append("selected frame bytes exceed max_bytes")
    elif replay_mode != "session" and not offline and total >= int(limits.get("max_bytes") or 0):
        errors.append("selected payload bytes leave no bounded capacity for response evidence")
    return _deduplicate(errors)


def _frame_payload(frame: Mapping[str, Any]) -> bytes:
    encoded = frame.get("payload_base64")
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("frame payload_base64 is missing")
    try:
        return base64.b64decode(encoded.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("frame payload_base64 is invalid") from exc


def _group_frames(frames: Sequence[dict[str, Any]]) -> OrderedDict[str, list[dict[str, Any]]]:
    groups: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
    for frame in frames:
        groups.setdefault(str(frame["connection_id"]), []).append(frame)
    return groups


def _new_socket(host: str) -> socket.socket:
    address = ipaddress.ip_address(host)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    value = socket.socket(family, socket.SOCK_STREAM)
    if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
        value.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    return value


def _new_datagram_socket(host: str) -> socket.socket:
    address = ipaddress.ip_address(host)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    value = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
        value.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    return value


def _socket_address(host: str, port: int) -> tuple[Any, ...]:
    if ipaddress.ip_address(host).version == 6:
        return host, port, 0, 0
    return host, port


def _socket_connection_identity(value: socket.socket) -> dict[str, Any]:
    real_socket = isinstance(value, _REAL_SOCKET_TYPE)
    result: dict[str, Any] = {
        "real_socket": real_socket,
        "synthetic": not real_socket,
    }
    if not real_socket:
        result["value_type"] = type(value).__name__
        return result
    try:
        result["local"] = _endpoint_identity(_address_mapping(value.getsockname()))
    except OSError as exc:
        result["local_error"] = str(exc) or exc.__class__.__name__
    try:
        result["peer"] = _endpoint_identity(_address_mapping(value.getpeername()))
    except OSError as exc:
        result["peer_error"] = str(exc) or exc.__class__.__name__
    result["tls"] = isinstance(value, ssl.SSLSocket)
    result["socket_type"] = "stream" if value.type & socket.SOCK_STREAM else str(value.type)
    return _prune(result)


def _socket_identity_is_real_loopback(value: Mapping[str, Any]) -> bool:
    return _socket_identity_matches_boundary(value, require_loopback=True)


def _socket_identity_matches_boundary(
    value: Mapping[str, Any],
    *,
    require_loopback: bool,
) -> bool:
    if value.get("real_socket") is not True or value.get("synthetic") is not False:
        return False
    local = _mapping(value.get("local"))
    peer = _mapping(value.get("peer"))
    if not local or not peer:
        return False
    if require_loopback:
        return local.get("loopback") is True and peer.get("loopback") is True
    return True


def _runtime_socket_identity_errors(
    value: socket.socket,
    *,
    expected_peer: Mapping[str, Any],
    require_loopback: bool,
) -> list[str]:
    identity = _socket_connection_identity(value)
    errors: list[str] = []
    if identity.get("real_socket") is not True or identity.get("synthetic") is not False:
        errors.append("protocol runtime requires a real operating-system socket")
        return errors
    local = _mapping(identity.get("local"))
    peer = _mapping(identity.get("peer"))
    if not local or not peer:
        errors.append("protocol runtime could not establish both socket endpoint identities")
        return errors
    if require_loopback and (
        local.get("loopback") is not True or peer.get("loopback") is not True
    ):
        errors.append("protocol runtime socket endpoints must both be loopback addresses")
    expected = _endpoint_identity(expected_peer)
    if (
        peer.get("host") != expected.get("host")
        or peer.get("port") != expected.get("port")
    ):
        errors.append(
            "protocol runtime connected peer identity does not match the planned endpoint"
        )
    return errors


def _real_loopback_socket_errors(
    value: socket.socket,
    *,
    expected_peer: Mapping[str, Any],
) -> list[str]:
    return _runtime_socket_identity_errors(
        value,
        expected_peer=expected_peer,
        require_loopback=True,
    )


def _connect_loopback(
    endpoint: Mapping[str, Any],
    *,
    deadline: float,
    timeout_ms: int,
    allow_remote: bool = False,
    tls: Optional[Mapping[str, Any]] = None,
) -> socket.socket:
    host = str(endpoint["host"])
    ok, reason = _endpoint_literal(host, allow_remote=allow_remote)
    if not ok:
        raise RuntimeError(reason)
    tls_config = _mapping(tls)
    context = _client_ssl_context(tls_config) if tls_config.get("enabled") else None
    value = _new_socket(host)
    value.settimeout(min(timeout_ms / 1_000.0, max(0.001, deadline - time.monotonic())))
    try:
        value.connect(_socket_address(host, int(endpoint["port"])))
        if context is not None:
            value.settimeout(
                min(timeout_ms / 1_000.0, max(0.001, deadline - time.monotonic()))
            )
            value = context.wrap_socket(
                value,
                server_hostname=str(tls_config.get("server_hostname") or host),
            )
    except Exception:
        value.close()
        raise
    return value


def _connect_udp_loopback(
    endpoint: Mapping[str, Any],
    *,
    deadline: float,
    timeout_ms: int,
    allow_remote: bool = False,
) -> socket.socket:
    host = str(endpoint["host"])
    ok, reason = _endpoint_literal(host, allow_remote=allow_remote)
    if not ok:
        raise RuntimeError(reason)
    value = _new_datagram_socket(host)
    value.settimeout(min(timeout_ms / 1_000.0, max(0.001, deadline - time.monotonic())))
    try:
        value.connect(_socket_address(host, int(endpoint["port"])))
    except Exception:
        value.close()
        raise
    return value


def _client_ssl_context(config: Mapping[str, Any]) -> ssl.SSLContext:
    ca_file = str(config.get("ca_file") or "")
    ca_data: str | bytes | None = None
    if ca_file:
        try:
            raw_ca = Path(ca_file).read_bytes()
        except OSError as exc:
            raise RuntimeError("TLS CA file could not be read") from exc
        if len(raw_ca) > _MAX_ARTIFACT_BYTES:
            raise RuntimeError("TLS CA file exceeds the bounded read limit")
        expected_hash = str(config.get("ca_file_sha256") or "")
        if not expected_hash or hashlib.sha256(raw_ca).hexdigest() != expected_hash:
            raise RuntimeError("TLS CA file changed after planning")
        try:
            ca_data = raw_ca.decode("ascii") if b"-----BEGIN" in raw_ca else raw_ca
        except UnicodeDecodeError as exc:
            raise RuntimeError("TLS CA file is not valid PEM or DER data") from exc

    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if ca_data is not None:
            context.load_verify_locations(cadata=ca_data)
    except (OSError, ssl.SSLError) as exc:
        raise RuntimeError("TLS CA file could not be loaded") from exc
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if not bool(config.get("verify")):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _tls_connection_evidence(
    value: socket.socket,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    audit = _tls_audit_config(config)
    visibility = _tls_traffic_visibility(config)
    if not isinstance(value, ssl.SSLSocket):
        return {**audit, "traffic_visibility": visibility}
    cipher = value.cipher()
    peer_certificate = value.getpeercert(binary_form=True)
    decoded_certificate = value.getpeercert() or {}
    certificate_sha256 = (
        hashlib.sha256(peer_certificate).hexdigest() if peer_certificate else None
    )
    certificate_identity = _prune(
        {
            "presented": bool(peer_certificate),
            "der_length": len(peer_certificate) if peer_certificate else 0,
            "sha256": certificate_sha256,
            "verification_enabled": bool(audit.get("verify")),
            "hostname_reference": audit.get("server_hostname"),
            "hostname_verified": bool(audit.get("verify") and peer_certificate),
            "subject": _certificate_name(decoded_certificate.get("subject")),
            "issuer": _certificate_name(decoded_certificate.get("issuer")),
            "serial_number": decoded_certificate.get("serialNumber"),
            "not_before": decoded_certificate.get("notBefore"),
            "not_after": decoded_certificate.get("notAfter"),
            "subject_alt_names": [
                {"type": str(item[0]), "value": str(item[1])}
                for item in decoded_certificate.get("subjectAltName", ())
                if isinstance(item, tuple) and len(item) == 2
            ],
        }
    )
    return _prune(
        {
            **audit,
            "handshake": {
                "completed": True,
                "verification_enabled": bool(audit.get("verify")),
                "server_hostname": audit.get("server_hostname"),
            },
            "negotiated_version": value.version(),
            "cipher": cipher[0] if cipher else None,
            "cipher_protocol": cipher[1] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "alpn_protocol": value.selected_alpn_protocol(),
            "compression": value.compression(),
            "session_reused": bool(value.session_reused),
            "peer_certificate_sha256": certificate_sha256,
            "peer_certificate": certificate_identity,
            "endpoint_identity": {
                "server_hostname": audit.get("server_hostname"),
                "certificate_sha256": certificate_sha256,
                "certificate_verified": bool(audit.get("verify") and peer_certificate),
            },
            "traffic_visibility": visibility,
        }
    )


def _certificate_name(value: Any) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return result
    for relative_name in value:
        if not isinstance(relative_name, Sequence) or isinstance(
            relative_name, (str, bytes, bytearray)
        ):
            continue
        for item in relative_name:
            if isinstance(item, tuple) and len(item) == 2:
                result.append({"name": str(item[0]), "value": str(item[1])})
    return result


def _send_udp_connected(
    value: socket.socket,
    data: bytes,
    *,
    deadline: float,
    timeout_ms: int,
) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("protocol runtime duration limit expired while sending UDP")
    value.settimeout(min(timeout_ms / 1_000.0, max(0.001, remaining)))
    sent = value.send(data)
    if sent != len(data):
        raise ConnectionError("protocol runtime UDP socket did not send the complete datagram")


def _send_udp_to(
    value: socket.socket,
    data: bytes,
    endpoint: tuple[Any, ...],
    *,
    deadline: float,
    timeout_ms: int,
) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("protocol runtime duration limit expired while forwarding UDP")
    value.settimeout(min(timeout_ms / 1_000.0, max(0.001, remaining)))
    sent = value.sendto(data, endpoint)
    if sent != len(data):
        raise ConnectionError("protocol runtime UDP socket did not forward the complete datagram")


def _proxy_connection(
    client: socket.socket,
    upstream: socket.socket,
    *,
    connection_id: str,
    deadline: float,
    limits: Mapping[str, Any],
    mutation: Mapping[str, Any],
    frames: list[dict[str, Any]],
    counters: dict[str, int],
    lifecycle: Optional[list[dict[str, Any]]] = None,
) -> Optional[str]:
    client.setblocking(False)
    upstream.setblocking(False)
    readers: dict[socket.socket, tuple[socket.socket, str]] = {
        client: (upstream, "client_to_server"),
        upstream: (client, "server_to_client"),
    }
    started = time.monotonic()
    tls_drain_deadline: Optional[float] = None
    while readers:
        if len(frames) >= int(limits["max_frames"]):
            return "max_frames"
        remaining_bytes = int(limits["max_bytes"]) - counters["observed_bytes"]
        if remaining_bytes <= 0:
            return "max_bytes"
        now = time.monotonic()
        if now >= deadline:
            return "duration_ms"
        if tls_drain_deadline is not None and now >= tls_drain_deadline:
            return None
        active_deadline = (
            min(deadline, tls_drain_deadline)
            if tls_drain_deadline is not None
            else deadline
        )
        remaining_time = active_deadline - now
        buffered_tls = [
            value
            for value in readers
            if isinstance(value, ssl.SSLSocket) and value.pending() > 0
        ]
        if buffered_tls:
            readable = buffered_tls
        else:
            readable, _, _ = select.select(
                list(readers),
                [],
                [],
                min(0.05, remaining_time),
            )
        if not readable:
            continue
        for source in readable:
            if len(frames) >= int(limits["max_frames"]):
                return "max_frames"
            remaining_bytes = int(limits["max_bytes"]) - counters["observed_bytes"]
            if remaining_bytes <= 0:
                return "max_bytes"
            destination, direction = readers[source]
            try:
                observed = source.recv(min(_RECV_BYTES, remaining_bytes))
            except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                continue
            except (ConnectionResetError, ssl.SSLZeroReturnError, ssl.SSLEOFError):
                observed = b""
            if not observed:
                readers.pop(source, None)
                event = {
                    "sequence": len(lifecycle or []) + 1,
                    "direction": direction,
                    "after_frame_sequence": len(frames),
                    "propagated": False,
                    "mode": "tls_bounded_drain"
                    if isinstance(destination, ssl.SSLSocket)
                    else "tcp_shutdown_write",
                }
                if isinstance(destination, ssl.SSLSocket):
                    # SSLSocket.shutdown() discards the TLS layer before doing a
                    # TCP half-close. Keep decrypting any final application data
                    # for one bounded idle interval instead.
                    tls_drain_deadline = (
                        time.monotonic() + int(limits["socket_timeout_ms"]) / 1_000.0
                    )
                    event["propagated"] = False
                else:
                    try:
                        destination.shutdown(socket.SHUT_WR)
                        event["propagated"] = True
                    except OSError:
                        event["propagated"] = False
                if lifecycle is not None:
                    lifecycle.append(event)
                continue
            forwarded, mutation_record, replacements = _mutate_frame(
                observed,
                direction=direction,
                specification=mutation,
            )
            _send_with_deadline(
                destination,
                forwarded,
                deadline=deadline,
                timeout_ms=int(limits["socket_timeout_ms"]),
            )
            counters["observed_bytes"] += len(observed)
            counters["forwarded_bytes"] += len(forwarded)
            counters["mutation_count"] += replacements
            if tls_drain_deadline is not None:
                tls_drain_deadline = (
                    time.monotonic() + int(limits["socket_timeout_ms"]) / 1_000.0
                )
            frames.append(
                _runtime_frame(
                    sequence=len(frames) + 1,
                    connection_id=connection_id,
                    direction=direction,
                    observed=observed,
                    forwarded=forwarded,
                    started=started,
                    mutation=mutation_record,
                )
            )
            remaining_bytes = int(limits["max_bytes"]) - counters["observed_bytes"]
            if remaining_bytes <= 0:
                return "max_bytes"
    return None


def _send_with_deadline(
    value: socket.socket,
    data: bytes,
    *,
    deadline: float,
    timeout_ms: int,
) -> None:
    view = memoryview(data)
    while view:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("protocol runtime duration limit expired while sending")
        _, writable, _ = select.select([], [value], [], min(timeout_ms / 1_000.0, remaining))
        if not writable:
            raise TimeoutError("protocol runtime socket send timed out")
        try:
            sent = value.send(view)
        except (BlockingIOError, ssl.SSLWantWriteError):
            continue
        except ssl.SSLWantReadError:
            readable, _, _ = select.select(
                [value],
                [],
                [],
                min(timeout_ms / 1_000.0, remaining),
            )
            if not readable:
                raise TimeoutError("protocol runtime TLS socket send timed out")
            continue
        if sent <= 0:
            raise ConnectionError("protocol runtime socket closed while sending")
        view = view[sent:]


def _replay_connect_half_close(
    value: socket.socket,
    event: Mapping[str, Any],
    *,
    deadline: float,
    timeout_ms: int,
) -> dict[str, Any]:
    direction = str(event.get("direction") or "")
    if direction == "client_to_server":
        if isinstance(value, ssl.SSLSocket):
            raise RuntimeError(
                "CONNECT half-close replay over TLS proxy transport is not supported"
            )
        value.shutdown(socket.SHUT_WR)
        observed = "local_write_shutdown"
    elif direction == "server_to_client":
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                "protocol runtime duration limit expired while verifying CONNECT half-close"
            )
        readable, _, _ = select.select(
            [value],
            [],
            [],
            min(timeout_ms / 1_000.0, remaining),
        )
        if not readable:
            raise TimeoutError("CONNECT tunnel peer half-close verification timed out")
        try:
            trailing = value.recv(1)
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            trailing = b""
        if trailing:
            raise RuntimeError(
                "CONNECT tunnel peer sent bytes after the retained transcript"
            )
        observed = "peer_eof"
    else:
        raise ValueError("CONNECT half-close direction is invalid")
    return {
        "sequence": int(event.get("sequence") or 0),
        "direction": direction,
        "after_source_frame_sequence": int(
            event.get("after_source_frame_sequence") or 0
        ),
        "requested_mode": str(event.get("mode") or ""),
        "observed": observed,
        "verified": True,
    }


def _recv_exact_with_deadline(
    value: socket.socket,
    length: int,
    *,
    deadline: float,
    timeout_ms: int,
) -> bytes:
    received = bytearray()
    while len(received) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        value.settimeout(min(timeout_ms / 1_000.0, max(0.001, remaining)))
        try:
            chunk = value.recv(length - len(received))
        except (socket.timeout, ssl.SSLWantReadError, ssl.SSLWantWriteError):
            break
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            break
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received)


def _wait_for_replay_timing(
    frame: Mapping[str, Any],
    *,
    state: dict[str, float],
    timing_scale: float,
    deadline: float,
) -> None:
    if timing_scale <= 0:
        return
    source_elapsed = _float_value(frame.get("elapsed_ms"), 0.0)
    if source_elapsed < 0:
        source_elapsed = 0.0
    if "source_base_ms" not in state:
        state["source_base_ms"] = source_elapsed
        state["runtime_base"] = time.monotonic()
        state["last_offset"] = 0.0
    offset = max(
        state["last_offset"],
        max(0.0, source_elapsed - state["source_base_ms"]) * timing_scale / 1_000.0,
    )
    state["last_offset"] = offset
    target = state["runtime_base"] + offset
    if target > deadline:
        raise RuntimeError("replay timing exceeds the duration limit")
    while True:
        remaining = target - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 0.05))


def _mutate_frame(
    data: bytes,
    *,
    direction: str,
    specification: Mapping[str, Any],
) -> tuple[bytes, Optional[dict[str, Any]], int]:
    if not specification.get("enabled") or specification.get("direction") not in {
        direction,
        "both",
    }:
        return data, None, 0
    find = bytes.fromhex(str(specification["find_hex"]))
    replacement = bytes.fromhex(str(specification["replace_hex"]))
    replacements = min(data.count(find), int(specification["max_replacements"]))
    if replacements <= 0:
        return data, None, 0
    forwarded = data.replace(find, replacement, replacements)
    return (
        forwarded,
        {
            "applied": True,
            "replacement_count": replacements,
            "find_hex": find.hex(),
            "replace_hex": replacement.hex(),
            "before": _bytes_evidence(data),
            "after": _bytes_evidence(forwarded),
        },
        replacements,
    )


def _runtime_frame(
    *,
    sequence: int,
    connection_id: str,
    direction: str,
    observed: bytes,
    forwarded: bytes,
    started: float,
    transport: str = "tcp",
    mutation: Optional[Mapping[str, Any]] = None,
    source_sequence: Any = None,
) -> dict[str, Any]:
    frame = {
        "sequence": sequence,
        "connection_id": connection_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": round((time.monotonic() - started) * 1_000, 3),
        "transport": transport,
        "direction": direction,
        "observed_length": len(observed),
        "observed_sha256": hashlib.sha256(observed).hexdigest(),
        "observed_payload_base64": base64.b64encode(observed).decode("ascii"),
        "length": len(forwarded),
        "sha256": hashlib.sha256(forwarded).hexdigest(),
        "payload_base64": base64.b64encode(forwarded).decode("ascii"),
        "mutation": dict(mutation) if mutation else {"applied": False},
        "source_sequence": source_sequence,
    }
    return _prune(frame)


def _bytes_evidence(data: bytes) -> dict[str, Any]:
    return {
        "length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _close_socket(value: Optional[socket.socket]) -> None:
    if value is None:
        return
    try:
        value.close()
    except OSError:
        pass


def _address_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, tuple) and len(value) >= 2:
        return {"host": str(value[0]), "port": int(value[1])}
    return {"address": str(value)}


def _audit_artifact(session_id: str, action: str, status: str) -> CapabilityArtifact:
    return CapabilityArtifact(
        path=f"protocol_runtime/{_safe_segment(session_id)}/{_safe_segment(action)}.json",
        kind="protocol-runtime-audit",
        description=f"Bounded protocol runtime evidence for {action}",
        metadata={
            "schema_version": _SCHEMA_VERSION,
            "session_id": session_id,
            "action": action,
            "status": status,
            "materialized": False,
        },
    )


def _manifest_entry(
    artifact: CapabilityArtifact,
    *,
    status: str,
    session_id: str,
    action: str,
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "path": artifact.path,
        "kind": artifact.kind,
        "tool": "protocol_runtime",
        "provider": ProtocolRuntimeProvider.provider_name,
        "status": status,
        "role": "protocol-runtime-audit",
        "session_id": session_id,
        "action": action,
        "materialized": False,
    }


def _artifact_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    after_snapshot = dict(result.after_snapshot)
    frames = list(after_snapshot.pop("frames", []) or [])
    flows = list(after_snapshot.pop("flows", []) or [])
    messages = list(after_snapshot.pop("messages", []) or [])
    request_response_pairs = list(
        after_snapshot.pop("request_response_pairs", []) or []
    )
    report_section = dict(result.report_section)
    report_after = _mapping(report_section.get("after_snapshot"))
    report_after.pop("frames", None)
    report_after.pop("flows", None)
    report_after.pop("messages", None)
    report_after.pop("request_response_pairs", None)
    report_section["after_snapshot"] = report_after
    return {
        "schema_version": _SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "status": result.status,
        "action": result.action,
        "session_id": result.session_id,
        "target_identity": _target_identity(result.target),
        "precondition_hash": result.provenance.get("precondition_hash"),
        "before_snapshot": dict(result.before_snapshot),
        "after_snapshot": after_snapshot,
        "rollback_plan": dict(result.rollback_plan),
        "provenance": dict(result.provenance),
        "frames": frames,
        "flows": flows,
        "messages": messages,
        "request_response_pairs": request_response_pairs,
        "report_section": report_section,
        "dashboard_trace": [dict(item) for item in result.dashboard_trace],
    }


def _artifact_destination(root: Path, relative_path: str) -> Path:
    relative = Path(str(relative_path).replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("protocol runtime artifact path must stay under the collection root")
    destination = (root / relative).resolve()
    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise ValueError("protocol runtime artifact escaped the collection root") from exc
    return destination


def _extended_filesystem_path(path: Path) -> Path:
    """Return a Windows extended-length path for deep artifact workspaces."""

    if os.name != "nt":
        return path
    raw = str(path)
    if raw.startswith("\\\\?\\"):
        return path
    if raw.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + raw[2:])
    return Path("\\\\?\\" + raw)


def _safe_segment(value: Any) -> str:
    text = _SAFE_SEGMENT_RE.sub("-", str(value or "session")).strip("-.")
    return text[:96] or "session"


def _target_identity(target: TargetIdentity) -> dict[str, Any]:
    return {
        key: value
        for key, value in {
            "kind": target.kind,
            "path": target.path,
            "pid": target.pid,
            "sha256": target.sha256,
            "display_name": target.display_name,
            "metadata": dict(target.metadata or {}),
        }.items()
        if value not in (None, "", {})
    }


def _target_has_identity(target: TargetIdentity) -> bool:
    return bool(target.kind) and any(
        value not in (None, "")
        for value in (target.path, target.pid, target.sha256, target.display_name)
    )


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _deduplicate(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if str(value)))


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


__all__ = [
    "ProtocolRuntimeMockProvider",
    "ProtocolRuntimeProvider",
]
