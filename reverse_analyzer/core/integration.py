from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from reverse_analyzer.core.audit import summarize_audit_records
from reverse_analyzer.core.ir import EvidenceGraph, SemanticIR
from reverse_analyzer.evidence import load_manifest, verify_manifest
from reverse_analyzer.providers import build_default_registry

DEFAULT_REPORT_SECTIONS = (
    "evidence_integrity",
    "memory_analysis",
    "patch_analysis",
    "engine_analysis",
    "android_analysis",
    "ios_analysis",
    "protocol_analysis",
    "gui_analysis",
    "source_reconstruction",
)


def ensure_platform_sections(report_data: Dict[str, Any]) -> Dict[str, Any]:
    for key in DEFAULT_REPORT_SECTIONS:
        report_data.setdefault(key, {"status": "unavailable"})
    report_data.setdefault("platform_core", {"status": "pending"})
    return report_data


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _stable_node_id(node_type: str, identity: Any) -> str:
    return f"{node_type}:sha256:{_stable_hash(identity)}"


def _sample_label(report_data: Dict[str, Any], sample_path: Optional[str]) -> str:
    sample = report_data.get("sample") if isinstance(report_data.get("sample"), dict) else {}
    return (
        report_data.get("sample_name")
        or report_data.get("target_name")
        or report_data.get("input_name")
        or sample.get("name")
        or sample.get("filename")
        or sample.get("path")
        or (Path(sample_path).name if sample_path else "sample")
    )


def _sample_path(report_data: Dict[str, Any], sample_path: Optional[str]) -> Optional[str]:
    sample = report_data.get("sample") if isinstance(report_data.get("sample"), dict) else {}
    return (
        sample_path
        or report_data.get("sample_path")
        or report_data.get("target_path")
        or report_data.get("input_path")
        or sample.get("path")
    )


def _sample_attr(report_data: Dict[str, Any], key: str) -> Any:
    sample = report_data.get("sample") if isinstance(report_data.get("sample"), dict) else {}
    return report_data.get(key) or sample.get(key)


_UNAVAILABLE_STATUSES = {
    "unavailable",
    "unsupported",
    "not_available",
    "not_run",
    "skipped",
}

_PARTIAL_STATUSES = {
    "partial",
    "degraded",
    "dependency_gated",
    "dependency_missing",
    "missing_dependency",
    "mock",
    "mocked",
    "fake",
    "fixture",
    "schema",
    "schema_only",
    "stub",
    "placeholder",
    "dry_run",
    "simulated",
    "planned",
    "unknown",
}

_FAILED_STATUSES = {"failed", "failure", "error", "invalid"}


def _normalized_status(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _meaningful_section(value: Any) -> bool:
    if not isinstance(value, dict):
        return bool(value)
    if not value:
        return False
    status = _normalized_status(value.get("status"))
    if status in _UNAVAILABLE_STATUSES and set(value) <= {"status"}:
        return False
    return True


def _derive_semantic_ir_status(ir: SemanticIR, existing_status: Any) -> str:
    explicit_status = _normalized_status(existing_status)
    payloads = [ir.engine, ir.android, ir.ios, ir.protocol, ir.gui, ir.source, *ir.runtime]
    meaningful_payloads = [payload for payload in payloads if _meaningful_section(payload)]
    status_signals = [
        _normalized_status(payload.get("status"))
        for payload in meaningful_payloads
        if isinstance(payload, dict) and payload.get("status")
    ]
    for note in ir.notes:
        if not isinstance(note, dict) or note.get("type") != "capability_audit":
            continue
        summary = note.get("summary") if isinstance(note.get("summary"), dict) else {}
        for record in summary.get("records") or []:
            if isinstance(record, dict) and record.get("status"):
                status_signals.append(_normalized_status(record.get("status")))

    structural_count = sum(
        len(items)
        for items in (
            ir.entities,
            ir.relations,
            ir.capabilities,
            ir.artifacts,
            ir.modules,
        )
    )
    has_content = bool(structural_count or meaningful_payloads or ir.notes)
    has_failure = explicit_status in _FAILED_STATUSES or any(
        status in _FAILED_STATUSES for status in status_signals
    )
    has_partial = explicit_status in _PARTIAL_STATUSES or any(
        status in _PARTIAL_STATUSES or status in _UNAVAILABLE_STATUSES
        for status in status_signals
    )

    if not has_content:
        return "failed" if has_failure else "unavailable"
    if explicit_status in _FAILED_STATUSES and not any(
        status not in _FAILED_STATUSES for status in status_signals
    ):
        return "failed"
    if has_failure or has_partial:
        return "partial"
    return "ok"


def _update_semantic_ir_summary(ir: SemanticIR) -> None:
    domain_payloads = {
        "engine": ir.engine,
        "android": ir.android,
        "ios": ir.ios,
        "protocol": ir.protocol,
        "gui": ir.gui,
        "source": ir.source,
    }
    ir.summary.update(
        {
            "entity_count": len(ir.entities),
            "relation_count": len(ir.relations),
            "capability_count": len(ir.capabilities),
            "artifact_count": len(ir.artifacts),
            "module_count": len(ir.modules),
            "runtime_count": len(ir.runtime),
            "note_count": len(ir.notes),
            "domain_statuses": {
                name: _normalized_status(payload.get("status")) or "unknown"
                for name, payload in domain_payloads.items()
                if _meaningful_section(payload)
            },
        }
    )


def build_semantic_ir(
    report_data: Dict[str, Any],
    sample_path: Optional[str] = None,
) -> SemanticIR:
    ensure_platform_sections(report_data)
    resolved_sample_path = _sample_path(report_data, sample_path)
    existing_ir = (
        report_data.get("semantic_ir")
        if isinstance(report_data.get("semantic_ir"), dict)
        else {}
    )

    ir = SemanticIR(
        status=str(existing_ir.get("status") or "unavailable"),
        schema_version=(
            existing_ir.get("schema_version")
            if isinstance(existing_ir.get("schema_version"), int)
            else 1
        ),
        entities=list(existing_ir.get("entities") or [])
        if isinstance(existing_ir.get("entities"), list)
        else [],
        relations=list(existing_ir.get("relations") or [])
        if isinstance(existing_ir.get("relations"), list)
        else [],
        capabilities=list(existing_ir.get("capabilities") or [])
        if isinstance(existing_ir.get("capabilities"), list)
        else [],
        summary=dict(existing_ir.get("summary") or {})
        if isinstance(existing_ir.get("summary"), dict)
        else {},
        artifacts=list(existing_ir.get("artifacts") or [])
        if isinstance(existing_ir.get("artifacts"), list)
        else [],
        sample={
            "name": _sample_label(report_data, resolved_sample_path),
            "path": resolved_sample_path,
            "sha256": _sample_attr(report_data, "sha256"),
            "platform": _sample_attr(report_data, "platform"),
            "file_type": _sample_attr(report_data, "file_type"),
        }
    )

    if _meaningful_section(report_data.get("memory_analysis")):
        ir.runtime.append(report_data["memory_analysis"])

    ir.engine = report_data.get("engine_analysis") or {}
    ir.android = report_data.get("android_analysis") or {}
    ir.ios = report_data.get("ios_analysis") or {}
    ir.protocol = report_data.get("protocol_analysis") or {}
    ir.gui = report_data.get("gui_analysis") or {}
    ir.source = report_data.get("source_reconstruction") or {}

    capability_audit = report_data.get("capability_audit") or {}
    if capability_audit:
        ir.notes.append({"type": "capability_audit", "summary": capability_audit})

    if report_data.get("static_analysis"):
        ir.modules.append(
            {
                "type": "static_analysis",
                "summary": report_data.get("static_analysis"),
            }
        )

    if report_data.get("imports"):
        ir.modules.append(
            {
                "type": "imports",
                "summary": report_data.get("imports"),
            }
        )

    pe_analysis = report_data.get("pe_analysis")
    if isinstance(pe_analysis, dict) and pe_analysis:
        ir.modules.append({"type": "pe_analysis", "summary": pe_analysis})

    ir.status = _derive_semantic_ir_status(ir, existing_ir.get("status"))

    _update_semantic_ir_summary(ir)

    return ir


_COMPLETED_STATUSES = {
    "ok",
    "success",
    "successful",
    "succeeded",
    "complete",
    "completed",
    "done",
    "available",
}
_MOCK_STATUSES = {"mock", "mocked", "simulated", "dry_run"}
_DEPENDENCY_GATED_STATUSES = {
    "dependency_gated",
    "dependency_missing",
    "missing_dependency",
}
_NON_PRODUCTION_STATUSES = {
    "fake",
    "fixture",
    "schema",
    "schema_only",
    "stub",
    "placeholder",
}


def _dependency_gated(payload: Mapping[str, Any]) -> bool:
    if _normalized_status(payload.get("status")) in _DEPENDENCY_GATED_STATUSES:
        return True
    if _normalized_status(payload.get("dependency_state")) in _UNAVAILABLE_STATUSES:
        return True
    for key in ("dependency", "capability_boundary"):
        value = payload.get(key)
        if not isinstance(value, Mapping):
            continue
        state = value.get("state") or value.get("status") or value.get("dependency_state")
        if _normalized_status(state) in _UNAVAILABLE_STATUSES:
            return True
    return False


def _analysis_edge_type(payload: Mapping[str, Any]) -> str:
    status = _normalized_status(payload.get("status"))
    provider = _normalized_status(payload.get("provider"))
    if status in _UNAVAILABLE_STATUSES:
        return "analysis_unavailable"
    if status in _FAILED_STATUSES:
        return "analysis_failed"
    if _dependency_gated(payload):
        return "analysis_dependency_gated"
    if status in _MOCK_STATUSES or provider == "mock" or payload.get("mock") is True:
        return "has_mock_analysis"
    if status in _NON_PRODUCTION_STATUSES or provider in _NON_PRODUCTION_STATUSES:
        return "has_non_production_analysis"
    if status in {"partial", "degraded"}:
        return "has_partial_analysis"
    if status in _COMPLETED_STATUSES:
        return "has_analysis"
    return "analysis_pending"


def _as_items(value: Any) -> Iterable[Any]:
    if value is None:
        return ()
    if isinstance(value, Mapping) or isinstance(value, (str, bytes, bytearray)):
        return (value,)
    if isinstance(value, Sequence):
        return value
    return (value,)


def _normalized_artifact_path(value: Any, base_dir: Optional[Path]) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    candidate = Path(raw)
    if candidate.is_absolute() and base_dir is not None:
        try:
            return candidate.resolve().relative_to(base_dir.resolve()).as_posix()
        except (OSError, ValueError):
            pass
    normalized = candidate.as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _resolved_path(value: Any, base_dir: Optional[Path]) -> Optional[Path]:
    if value in (None, ""):
        return None
    candidate = Path(str(value))
    if not candidate.is_absolute() and base_dir is not None:
        candidate = base_dir / candidate
    try:
        return candidate.resolve()
    except OSError:
        return candidate


def _verification_issues(verification: Optional[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    if verification is None:
        return []

    unique: Dict[str, Dict[str, Any]] = {}
    for field_name in ("issues", "failures"):
        for item in _as_items(verification.get(field_name)):
            if isinstance(item, Mapping):
                issue = {str(key): value for key, value in item.items()}
            elif item not in (None, ""):
                issue = {"kind": "verification_failure", "detail": str(item)}
            else:
                continue
            unique[_stable_hash(issue)] = issue

    status = _normalized_status(verification.get("status"))
    if not unique and (status in _FAILED_STATUSES or verification.get("valid") is False):
        issue = {
            "kind": "verification_failed",
            "detail": (
                verification.get("error")
                or verification.get("reason")
                or verification.get("detail")
                or "verification reported failure without issue details"
            ),
        }
        unique[_stable_hash(issue)] = issue
    return [unique[key] for key in sorted(unique)]


def _execution_kind(record: Mapping[str, Any]) -> str:
    status = _normalized_status(record.get("status"))
    provider = _normalized_status(record.get("provider"))
    if status in _UNAVAILABLE_STATUSES:
        return "unavailable"
    if status in _FAILED_STATUSES:
        return "failed"
    if _dependency_gated(record):
        return "dependency_gated"
    if status in _MOCK_STATUSES or provider == "mock":
        return "mock"
    if status in _NON_PRODUCTION_STATUSES or provider in _NON_PRODUCTION_STATUSES:
        return "non_production"
    if status in _COMPLETED_STATUSES:
        return "completed"
    if status in {"partial", "degraded"}:
        return "partial"
    return "unknown"


class _EvidenceGraphIngestor:
    def __init__(
        self,
        graph: EvidenceGraph,
        sample_node_id: str,
        base_dir: Optional[Path],
    ) -> None:
        self.graph = graph
        self.sample_node_id = sample_node_id
        self.base_dir = base_dir
        self.artifacts: Dict[str, str] = {}

    def _add_hash(self, owner_id: str, digest: Any, edge_type: str, **properties: Any) -> None:
        value = str(digest or "").strip().lower()
        if value.startswith("sha256:"):
            value = value.split(":", 1)[1]
        if not value:
            return
        node_id = f"artifact_hash:sha256:{value}"
        self.graph.add_node(
            node_id,
            "artifact_hash",
            f"sha256:{value}",
            algorithm="sha256",
            digest=value,
        )
        edge_properties = dict(properties)
        for reserved_name in ("source", "target", "edge_type"):
            if reserved_name in edge_properties:
                edge_properties[f"evidence_{reserved_name}"] = edge_properties.pop(reserved_name)
        self.graph.add_edge(owner_id, node_id, edge_type, **edge_properties)

    def add_artifact(
        self,
        record: Mapping[str, Any],
        source: str,
        *,
        execution_kind: Optional[str] = None,
    ) -> Optional[str]:
        path = _normalized_artifact_path(record.get("path"), self.base_dir)
        if not path:
            return None
        node_id = _stable_node_id("artifact", {"path": path})
        properties = {str(key): value for key, value in record.items() if key != "path"}
        properties["path"] = path
        properties.setdefault("ingested_from", source)
        if execution_kind:
            properties.setdefault("execution_kind", execution_kind)
        self.graph.add_node(node_id, "artifact", path, **properties)
        self.artifacts[path] = node_id
        digest = record.get("sha256")
        if digest:
            self._add_hash(node_id, digest, "has_declared_hash", source=source)
        return node_id

    def add_evidence_references(
        self,
        owner_id: str,
        value: Any,
        *,
        field_name: str,
        execution_kind: Optional[str] = None,
    ) -> None:
        for reference in _as_items(value):
            if reference in (None, ""):
                continue
            if isinstance(reference, Mapping) and reference.get("path"):
                target_id = self.add_artifact(
                    reference,
                    field_name,
                    execution_kind=execution_kind,
                )
                if target_id is not None:
                    self.graph.add_edge(
                        owner_id,
                        target_id,
                        "references_evidence",
                        reference_field=field_name,
                        execution_kind=execution_kind,
                    )
                continue

            if isinstance(reference, str):
                artifact_id = self.artifacts.get(
                    _normalized_artifact_path(reference, self.base_dir)
                )
                if artifact_id is not None:
                    self.graph.add_edge(
                        owner_id,
                        artifact_id,
                        "references_evidence",
                        reference_field=field_name,
                        execution_kind=execution_kind,
                    )
                    continue
                label = reference
                properties: Dict[str, Any] = {"reference": reference}
            else:
                label = str(
                    reference.get("name")
                    or reference.get("id")
                    or reference.get("kind")
                    or field_name
                ) if isinstance(reference, Mapping) else str(reference)
                properties = {"reference": dict(reference)} if isinstance(reference, Mapping) else {"reference": reference}

            reference_id = _stable_node_id(
                "evidence_reference",
                {"field": field_name, "reference": reference},
            )
            self.graph.add_node(
                reference_id,
                "evidence_reference",
                label,
                **properties,
            )
            self.graph.add_edge(
                owner_id,
                reference_id,
                "has_evidence_reference",
                reference_field=field_name,
                execution_kind=execution_kind,
            )

    def _manifest_source(
        self,
        report_data: Mapping[str, Any],
    ) -> tuple[
        Optional[Dict[str, Any]],
        Optional[Path],
        Dict[str, Any],
        Optional[Dict[str, Any]],
    ]:
        direct = report_data.get("evidence_manifest")
        integrity = report_data.get("evidence_integrity")
        summary = dict(integrity) if isinstance(integrity, Mapping) else {}
        payload: Optional[Dict[str, Any]] = None
        reported_verification: Optional[Dict[str, Any]] = None
        raw_path: Any = None

        if isinstance(direct, Mapping):
            nested = direct.get("manifest")
            if isinstance(nested, Mapping):
                nested_payload = nested.get("manifest")
                if isinstance(nested_payload, Mapping):
                    payload = dict(nested_payload)
                elif any(key in nested for key in ("schema", "manifest_id", "artifacts")):
                    payload = dict(nested)
                raw_path = nested.get("manifest_path") or nested.get("path")
            elif any(key in direct for key in ("schema", "manifest_id", "artifacts")):
                payload = dict(direct)
            raw_path = direct.get("manifest_path") or direct.get("path") or raw_path
            if isinstance(direct.get("verification"), Mapping):
                reported_verification = dict(direct["verification"])
        elif direct not in (None, ""):
            raw_path = direct

        nested_summary = summary.get("manifest")
        if isinstance(nested_summary, Mapping):
            nested_payload = nested_summary.get("manifest")
            if payload is None and isinstance(nested_payload, Mapping):
                payload = dict(nested_payload)
            elif payload is None and any(
                key in nested_summary for key in ("schema", "manifest_id", "artifacts")
            ):
                payload = dict(nested_summary)
            raw_path = (
                raw_path
                or nested_summary.get("manifest_path")
                or nested_summary.get("path")
            )
            if reported_verification is None and isinstance(
                nested_summary.get("verification"), Mapping
            ):
                reported_verification = dict(nested_summary["verification"])
        elif nested_summary not in (None, ""):
            raw_path = raw_path or nested_summary

        if payload is None and any(
            key in summary for key in ("schema", "manifest_id", "artifacts")
        ):
            payload = dict(summary)
        if raw_path in (None, ""):
            raw_path = summary.get("manifest_path") or summary.get("path")
        if reported_verification is None and isinstance(summary.get("verification"), Mapping):
            reported_verification = dict(summary["verification"])
        if reported_verification is None and any(
            key in summary for key in ("valid", "issues", "failures")
        ):
            reported_verification = dict(summary)
        return (
            payload,
            _resolved_path(raw_path, self.base_dir),
            summary,
            reported_verification,
        )

    def ingest_manifest(self, report_data: Mapping[str, Any]) -> None:
        payload, manifest_path, summary, verification = self._manifest_source(report_data)
        verification_source = "reported" if verification is not None else "unavailable"
        if manifest_path is not None:
            verification = verify_manifest(manifest_path)
            verification_source = "live"
            try:
                payload = load_manifest(manifest_path)
            except (OSError, ValueError, json.JSONDecodeError):
                pass

        if payload is None and manifest_path is None and verification is None:
            return

        manifest_id = (
            (payload or {}).get("manifest_id")
            or (verification or {}).get("manifest_id")
            or summary.get("manifest_id")
        )
        manifest_identity: Any = manifest_id
        if not manifest_identity:
            manifest_identity = (
                {"path": str(manifest_path)}
                if manifest_path is not None
                else {"manifest": payload, "verification": verification}
            )
        manifest_node_id = _stable_node_id("evidence_manifest", manifest_identity)
        self.graph.add_node(
            manifest_node_id,
            "evidence_manifest",
            manifest_path.name if manifest_path is not None else "evidence-manifest.json",
            path=str(manifest_path) if manifest_path is not None else None,
            manifest_id=manifest_id,
            schema=(payload or {}).get("schema"),
            hash_algorithm=(payload or {}).get("hash_algorithm") or summary.get("hash_algorithm"),
            reported_status=summary.get("status"),
            verification_status=(verification or {}).get("status") or "unavailable",
            verification_source=verification_source,
            valid=(verification or {}).get("valid"),
        )
        self.graph.add_edge(
            self.sample_node_id,
            manifest_node_id,
            "has_evidence_manifest",
        )

        manifest_sample = (payload or {}).get("sample")
        if isinstance(manifest_sample, Mapping):
            self.graph.add_edge(
                manifest_node_id,
                self.sample_node_id,
                "declares_sample",
                status=manifest_sample.get("status"),
                path=manifest_sample.get("path"),
                verification_scope=manifest_sample.get("verification_scope"),
            )
            self._add_hash(
                self.sample_node_id,
                manifest_sample.get("sha256"),
                "has_declared_hash",
                source="evidence_manifest.sample",
            )

        issues = _verification_issues(verification)
        issue_paths = {
            _normalized_artifact_path(item.get("path"), self.base_dir)
            for item in issues
            if item.get("path")
        }
        for artifact in (payload or {}).get("artifacts") or []:
            if not isinstance(artifact, Mapping) or not artifact.get("path"):
                continue
            artifact_payload = dict(artifact)
            normalized_path = _normalized_artifact_path(artifact.get("path"), self.base_dir)
            if verification is None:
                artifact_payload["verification_status"] = "unverified"
            elif normalized_path in issue_paths:
                artifact_payload["verification_status"] = "failed"
            elif _normalized_status(artifact.get("status")) not in _COMPLETED_STATUSES:
                artifact_payload["verification_status"] = "skipped"
            elif artifact.get("sha256"):
                artifact_payload["verification_status"] = "verified"
            else:
                artifact_payload["verification_status"] = "not_hash_covered"
            artifact_id = self.add_artifact(artifact_payload, "evidence_manifest")
            if artifact_id is not None:
                self.graph.add_edge(
                    manifest_node_id,
                    artifact_id,
                    "declares_artifact",
                    status=artifact.get("status"),
                )

        for derivation in (payload or {}).get("derivations") or []:
            if not isinstance(derivation, Mapping):
                continue
            target_path = _normalized_artifact_path(derivation.get("to"), self.base_dir)
            target_id = self.artifacts.get(target_path)
            if target_id is None:
                continue
            source_value = str(derivation.get("from") or "sample")
            source_id = self.sample_node_id
            if source_value != "sample":
                source_id = self.artifacts.get(
                    _normalized_artifact_path(source_value, self.base_dir),
                    "",
                )
            if source_id:
                self.graph.add_edge(
                    source_id,
                    target_id,
                    "generated_artifact",
                    generated_by=derivation.get("generated_by"),
                )

        if verification is not None:
            verification_node_id = _stable_node_id(
                "evidence_verification",
                {
                    "manifest": manifest_node_id,
                    "status": verification.get("status"),
                    "expected_manifest_id": verification.get("expected_manifest_id"),
                    "issues": issues,
                },
            )
            self.graph.add_node(
                verification_node_id,
                "evidence_verification",
                "manifest verification",
                status=verification.get("status"),
                valid=verification.get("valid"),
                verification_source=verification_source,
                verified_file_count=verification.get("verified_file_count"),
                skipped_file_count=verification.get("skipped_file_count"),
                manifest_id=verification.get("manifest_id"),
                expected_manifest_id=verification.get("expected_manifest_id"),
            )
            self.graph.add_edge(
                manifest_node_id,
                verification_node_id,
                "has_verification",
            )
            for issue in issues:
                issue_id = _stable_node_id(
                    "integrity_failure",
                    {"manifest": manifest_node_id, "issue": issue},
                )
                self.graph.add_node(
                    issue_id,
                    "integrity_failure",
                    str(issue.get("kind") or "verification failure"),
                    **issue,
                )
                self.graph.add_edge(
                    verification_node_id,
                    issue_id,
                    "has_integrity_failure",
                )
                artifact_id = self.artifacts.get(
                    _normalized_artifact_path(issue.get("path"), self.base_dir)
                )
                if artifact_id is not None:
                    self.graph.add_edge(issue_id, artifact_id, "affects_artifact")
                if issue.get("expected") and issue.get("kind") == "hash":
                    self._add_hash(issue_id, issue.get("expected"), "expected_hash")
                if issue.get("actual") and issue.get("kind") == "hash":
                    self._add_hash(issue_id, issue.get("actual"), "observed_hash")
                    if artifact_id is not None:
                        self._add_hash(
                            artifact_id,
                            issue.get("actual"),
                            "has_observed_hash",
                            verification_status="failed",
                        )
        elif _normalized_status(summary.get("status")) in _FAILED_STATUSES:
            issue = {
                "kind": "reported_integrity_failure",
                "detail": summary.get("error") or summary.get("reason"),
            }
            issue_id = _stable_node_id(
                "integrity_failure",
                {"manifest": manifest_node_id, "issue": issue},
            )
            self.graph.add_node(
                issue_id,
                "integrity_failure",
                "reported integrity failure",
                **issue,
            )
            self.graph.add_edge(manifest_node_id, issue_id, "has_integrity_failure")

    def ingest_semantic_ir(self, semantic_ir: SemanticIR | Mapping[str, Any]) -> None:
        payload = semantic_ir.to_dict() if isinstance(semantic_ir, SemanticIR) else dict(semantic_ir)
        root_id = _stable_node_id(
            "semantic_ir",
            {
                "sample": self.sample_node_id,
                "schema_version": payload.get("schema_version", 1),
            },
        )
        status = _normalized_status(payload.get("status")) or "unknown"
        self.graph.add_node(
            root_id,
            "semantic_ir",
            "Semantic IR",
            status=status,
            schema_version=payload.get("schema_version", 1),
            summary=payload.get("summary"),
        )
        root_edge_type = "has_semantic_ir"
        if status in _UNAVAILABLE_STATUSES:
            root_edge_type = "semantic_ir_unavailable"
        elif status in _MOCK_STATUSES:
            root_edge_type = "has_mock_semantic_ir"
        elif status in _DEPENDENCY_GATED_STATUSES:
            root_edge_type = "semantic_ir_dependency_gated"
        elif status in _NON_PRODUCTION_STATUSES:
            root_edge_type = "has_non_production_semantic_ir"
        elif status in _FAILED_STATUSES:
            root_edge_type = "semantic_ir_failed"
        self.graph.add_edge(self.sample_node_id, root_id, root_edge_type, status=status)

        aliases: Dict[str, str] = {}
        for entity in payload.get("entities") or []:
            if not isinstance(entity, Mapping):
                continue
            semantic_id = str(entity.get("id") or "")
            node_id = semantic_id or _stable_node_id("semantic_entity", entity)
            existing = next((node for node in self.graph.nodes if node.node_id == node_id), None)
            if existing is not None and existing.node_type != "semantic_entity":
                node_id = _stable_node_id("semantic_entity", {"semantic_id": semantic_id})
            name = entity.get("name") or entity.get("label") or semantic_id or entity.get("kind") or "entity"
            properties = {
                str(key): value
                for key, value in entity.items()
                if key not in {"id", "name", "label"}
            }
            properties["semantic_id"] = semantic_id or node_id
            self.graph.add_node(node_id, "semantic_entity", str(name), **properties)
            self.graph.add_edge(root_id, node_id, "contains_entity")
            aliases[node_id] = node_id
            if semantic_id:
                aliases[semantic_id] = node_id
            for field_name in ("sources", "evidence", "evidence_refs", "evidence_references"):
                if entity.get(field_name) is not None:
                    self.add_evidence_references(
                        node_id,
                        entity.get(field_name),
                        field_name=f"semantic_entity.{field_name}",
                    )

        for relation in payload.get("relations") or []:
            if not isinstance(relation, Mapping):
                continue
            source_value = str(relation.get("source") or "")
            target_value = str(relation.get("target") or "")
            source_id = aliases.get(source_value)
            target_id = aliases.get(target_value)
            missing = [
                endpoint
                for endpoint, resolved in ((source_value, source_id), (target_value, target_id))
                if not endpoint or resolved is None
            ]
            if missing:
                issue_id = _stable_node_id(
                    "integrity_failure",
                    {"semantic_ir": root_id, "relation": relation, "missing": missing},
                )
                self.graph.add_node(
                    issue_id,
                    "integrity_failure",
                    "semantic relation endpoint missing",
                    kind="dangling_semantic_relation",
                    relation_id=relation.get("id"),
                    relation_type=(
                        relation.get("type")
                        or relation.get("kind")
                        or relation.get("relation")
                    ),
                    source=source_value,
                    target=target_value,
                    missing_endpoints=missing,
                )
                self.graph.add_edge(root_id, issue_id, "has_integrity_failure")
                continue

            relation_type = str(
                relation.get("type")
                or relation.get("kind")
                or relation.get("relation")
                or "related_to"
            )
            relation_properties = {
                str(key): value
                for key, value in relation.items()
                if key not in {"source", "target", "type", "kind", "relation", "edge_type"}
            }
            self.graph.add_edge(source_id, target_id, relation_type, **relation_properties)
            relation_node_id = _stable_node_id(
                "semantic_relation",
                relation.get("id") or relation,
            )
            self.graph.add_node(
                relation_node_id,
                "semantic_relation",
                relation_type,
                source=source_value,
                target=target_value,
                **relation_properties,
            )
            self.graph.add_edge(root_id, relation_node_id, "contains_relation")
            self.graph.add_edge(relation_node_id, source_id, "relation_source")
            self.graph.add_edge(relation_node_id, target_id, "relation_target")
            for field_name in ("sources", "evidence", "evidence_refs", "evidence_references"):
                if relation.get(field_name) is not None:
                    self.add_evidence_references(
                        relation_node_id,
                        relation.get(field_name),
                        field_name=f"semantic_relation.{field_name}",
                    )

        for artifact in payload.get("artifacts") or []:
            if not isinstance(artifact, Mapping):
                continue
            artifact_id = self.add_artifact(artifact, "semantic_ir")
            if artifact_id is not None:
                self.graph.add_edge(root_id, artifact_id, "references_evidence")

    def ingest_capability_audit(self, capability_audit: Any) -> None:
        if isinstance(capability_audit, Mapping):
            records = capability_audit.get("records") or []
        elif isinstance(capability_audit, Sequence) and not isinstance(
            capability_audit, (str, bytes, bytearray)
        ):
            records = capability_audit
        else:
            return

        for record in records:
            if not isinstance(record, Mapping):
                continue
            identity = {
                key: record.get(key)
                for key in (
                    "session_id",
                    "capability",
                    "provider",
                    "action",
                    "precondition_hash",
                    "target_identity",
                )
                if record.get(key) not in (None, "", {}, [])
            } or dict(record)
            node_id = _stable_node_id("capability_audit", identity)
            execution_kind = _execution_kind(record)
            self.graph.add_node(
                node_id,
                "capability_audit",
                str(record.get("capability") or record.get("session_id") or "capability audit"),
                session_id=record.get("session_id"),
                status=record.get("status"),
                provider=record.get("provider"),
                action=record.get("action"),
                precondition_hash=record.get("precondition_hash"),
                target_identity=record.get("target_identity"),
                execution_kind=execution_kind,
            )
            self.graph.add_edge(
                self.sample_node_id,
                node_id,
                "has_audit_record",
                execution_kind=execution_kind,
            )

            provenance = record.get("provenance")
            if provenance not in (None, "", {}, []):
                provenance_id = _stable_node_id(
                    "audit_provenance",
                    {"audit": node_id, "provenance": provenance},
                )
                self.graph.add_node(
                    provenance_id,
                    "audit_provenance",
                    "capability provenance",
                    provenance=provenance,
                )
                self.graph.add_edge(node_id, provenance_id, "has_provenance")

            dashboard_trace = record.get("dashboard_trace")
            if isinstance(dashboard_trace, Mapping) and isinstance(
                dashboard_trace.get("steps"), Sequence
            ) and not isinstance(
                dashboard_trace.get("steps"), (str, bytes, bytearray)
            ):
                trace_items = dashboard_trace.get("steps") or []
            else:
                trace_items = _as_items(dashboard_trace)
            for trace in trace_items:
                if trace in (None, "", {}, []):
                    continue
                trace_id = _stable_node_id(
                    "dashboard_trace",
                    {"audit": node_id, "trace": trace},
                )
                if isinstance(trace, Mapping):
                    trace_label = trace.get("name") or trace.get("step") or trace.get("kind") or trace.get("action")
                else:
                    trace_label = trace
                self.graph.add_node(
                    trace_id,
                    "dashboard_trace",
                    str(trace_label or "dashboard trace"),
                    trace=trace,
                    execution_kind=execution_kind,
                )
                self.graph.add_edge(node_id, trace_id, "has_dashboard_trace")

            for entry in _as_items(record.get("evidence_manifest_entries")):
                self.add_evidence_references(
                    node_id,
                    entry,
                    field_name="capability_audit.evidence_manifest_entries",
                    execution_kind=execution_kind,
                )


def build_evidence_graph(
    report_data: Dict[str, Any],
    sample_path: Optional[str] = None,
    *,
    semantic_ir: Optional[SemanticIR | Mapping[str, Any]] = None,
    base_dir: Optional[str | Path] = None,
) -> EvidenceGraph:
    ensure_platform_sections(report_data)
    resolved_sample_path = _sample_path(report_data, sample_path)
    label = _sample_label(report_data, resolved_sample_path)
    sample_node_id = _stable_node_id(
        "sample",
        {"path": resolved_sample_path, "label": label},
    )

    graph = EvidenceGraph()
    graph.add_node(
        sample_node_id,
        "sample",
        label,
        path=resolved_sample_path,
        sha256=_sample_attr(report_data, "sha256"),
        platform=_sample_attr(report_data, "platform"),
        file_type=_sample_attr(report_data, "file_type"),
    )
    ingestor = _EvidenceGraphIngestor(
        graph,
        sample_node_id,
        Path(base_dir) if base_dir is not None else None,
    )
    ingestor.ingest_manifest(report_data)

    section_to_node_type = {
        "evidence_integrity": "evidence_integrity",
        "memory_analysis": "memory_analysis",
        "patch_analysis": "patch_analysis",
        "engine_analysis": "engine_analysis",
        "android_analysis": "android_analysis",
        "ios_analysis": "ios_analysis",
        "protocol_analysis": "protocol_analysis",
        "gui_analysis": "gui_analysis",
        "source_reconstruction": "source_reconstruction",
    }
    for section_name, node_type in section_to_node_type.items():
        payload = report_data.get(section_name) or {}
        if not isinstance(payload, Mapping):
            payload = {"value": payload}
        node_id = _stable_node_id(section_name, payload)
        strategy = payload.get("strategy") if isinstance(payload.get("strategy"), Mapping) else {}
        label_value = (
            payload.get("framework")
            or payload.get("engine")
            or strategy.get("name")
            or section_name
        )
        execution_kind = _execution_kind(payload)
        graph.add_node(
            node_id,
            node_type,
            str(label_value),
            status=payload.get("status", "unknown"),
            confidence=payload.get("confidence"),
            execution_kind=execution_kind,
        )
        graph.add_edge(
            sample_node_id,
            node_id,
            _analysis_edge_type(payload),
            section=section_name,
            status=payload.get("status", "unknown"),
            execution_kind=execution_kind,
        )
        for field_name in ("sources", "evidence", "evidence_refs", "evidence_references"):
            if payload.get(field_name) is not None:
                ingestor.add_evidence_references(
                    node_id,
                    payload.get(field_name),
                    field_name=f"{section_name}.{field_name}",
                )

    resolved_ir = (
        semantic_ir
        if semantic_ir is not None
        else build_semantic_ir(report_data, sample_path=sample_path)
    )
    ingestor.ingest_semantic_ir(resolved_ir)
    ingestor.ingest_capability_audit(report_data.get("capability_audit"))
    return graph


def summarize_registry(registry=None) -> Dict[str, Any]:
    registry = registry or build_default_registry()
    capabilities = registry.list_capabilities()
    return {
        "capability_count": len(capabilities),
        "capabilities": {
            capability: registry.list_providers(capability)
            for capability in capabilities
        },
    }


def summarize_capability_audit(report_data: Dict[str, Any]) -> Dict[str, Any]:
    capability_audit = report_data.get("capability_audit")
    if not isinstance(capability_audit, dict):
        return {"record_count": 0, "records": [], "summary": summarize_audit_records([])}
    records = capability_audit.get("records")
    if not isinstance(records, list):
        records = []
    return {
        "record_count": len(records),
        "records": records,
        "summary": summarize_audit_records(records),
    }


def finalize_platform_core(
    report_data: Dict[str, Any],
    out_dir: str,
    sample_path: Optional[str] = None,
    registry=None,
) -> Dict[str, Any]:
    ensure_platform_sections(report_data)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    ir = build_semantic_ir(report_data, sample_path=sample_path)
    graph = build_evidence_graph(
        report_data,
        sample_path=sample_path,
        semantic_ir=ir,
        base_dir=out_path,
    )
    registry_summary = summarize_registry(registry)

    semantic_ir_path = out_path / "semantic_ir.json"
    evidence_graph_path = out_path / "evidence_graph.json"

    ir.write_json(str(semantic_ir_path))
    graph.write_json(str(evidence_graph_path))

    report_data["platform_core"] = {
        "status": "ok",
        "semantic_ir": {
            "path": str(semantic_ir_path),

            "status": ir.status,

            "entity_count": len(ir.entities),

            "relation_count": len(ir.relations),

            "capability_count": len(ir.capabilities),

            "artifact_count": len(ir.artifacts),
            "module_count": len(ir.modules),
            "runtime_count": len(ir.runtime),
        },
        "evidence_graph": {
            "path": str(evidence_graph_path),
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
        },
        "capability_registry": registry_summary,
        "capability_audit": summarize_capability_audit(report_data),
    }

    return report_data["platform_core"]
