"""Evidence-bounded source equivalence assessment.

The assessor consumes already collected, JSON-like evidence.  It does not run
the reconstructed project and it never claims perfect source equivalence.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any


EQUIVALENCE_ASSESSMENT_SCHEMA_VERSION = 1
DEFAULT_EQUIVALENCE_ASSESSMENT_PATH = "analysis/equivalence_assessment.json"

EQUIVALENCE_DIMENSIONS = (
    "static_structure_coverage",
    "function_body_recovery",
    "compile_result",
    "runtime_differential_traces",
    "gui_matches",
    "protocol_matches",
    "behavior_matches",
)

DEFAULT_EQUIVALENCE_THRESHOLDS: dict[str, float | int] = {
    "overall_score": 1.0,
    "static_structure_coverage": 1.0,
    "function_body_recovery": 1.0,
    "compile_result": 1.0,
    "runtime_differential_traces": 1.0,
    "gui_matches": 1.0,
    "protocol_matches": 1.0,
    "behavior_matches": 1.0,
    "minimum_runtime_trace_count": 1,
    "minimum_gui_match_count": 1,
    "minimum_protocol_match_count": 1,
    "minimum_behavior_match_count": 1,
}

_ASSESSOR_VERSION = "1.0"
_MATCHED_STATUSES = frozenset({"matched", "passed", "validated", "ok", "succeeded"})
_MISMATCH_STATUSES = frozenset({"different", "failed", "mismatch", "mismatched"})
_UNAVAILABLE_STATUSES = frozenset({"not_available", "not_run", "tool_unavailable", "unavailable"})
_FUNCTION_KINDS = frozenset({"callback", "function", "handler", "method", "procedure"})
_STRUCTURE_KINDS = _FUNCTION_KINDS | frozenset(
    {"class", "enum", "interface", "module", "namespace", "struct", "type"}
)
_MAX_ITEMS = 512
_MAX_PROVENANCE_REFS = 64
_MAX_TEXT = 2048


def assess_source_equivalence(
    evidence: Mapping[str, Any] | None = None,
    *,
    semantic_ir: Mapping[str, Any] | None = None,
    project: Mapping[str, Any] | None = None,
    body_recovery: Mapping[str, Any] | None = None,
    compilation: Mapping[str, Any] | None = None,
    runtime_differential_traces: Mapping[str, Any] | Sequence[Any] | None = None,
    gui_matches: Mapping[str, Any] | Sequence[Any] | None = None,
    protocol_matches: Mapping[str, Any] | Sequence[Any] | None = None,
    behavior_matches: Mapping[str, Any] | Sequence[Any] | None = None,
    provenance: Mapping[str, Any] | Sequence[Any] | str | None = None,
    thresholds: Mapping[str, Any] | None = None,
    skeleton: bool | None = None,
) -> dict[str, Any]:
    """Build a machine-readable, evidence-bounded equivalence assessment.

    ``evidence`` may be a reconstruction result or a purpose-built fixture.
    Explicit keyword arguments take precedence over fields in that mapping.
    No dimension is inferred as passing merely because another dimension did.
    """

    if evidence is None:
        base: Mapping[str, Any] = {}
    elif isinstance(evidence, Mapping):
        base = evidence
    else:
        raise TypeError("evidence must be a mapping or None")
    if skeleton is not None and not isinstance(skeleton, bool):
        raise TypeError("skeleton must be a boolean or None")

    normalized_thresholds = _normalize_thresholds(thresholds)
    semantic_value = _mapping_or_none(
        semantic_ir,
        base.get("semantic_ir"),
        _nested(base, "analysis", "semantic_ir"),
        _nested(base, "equivalence_evidence", "semantic_ir"),
    )
    project_value = _mapping_or_none(
        project,
        base.get("project"),
        base.get("reconstructed_project"),
    )
    body_value = _mapping_or_none(
        body_recovery,
        base.get("body_recovery"),
        _nested(base, "analysis", "body_recovery"),
    )
    compile_value = _mapping_or_none(
        compilation,
        base.get("compilation"),
        base.get("compile_result"),
        base.get("validation"),
        _compile_evidence_from_runtime(base.get("runtime_validation")),
    )
    behavior_value = _evidence_value(
        behavior_matches,
        base.get("behavior_matches"),
        base.get("behavior_validation"),
        _nested(base, "equivalence_evidence", "behavior_matches"),
    )
    runtime_value = _evidence_value(
        runtime_differential_traces,
        base.get("runtime_differential_traces"),
        base.get("runtime_differential"),
        _nested(base, "equivalence_evidence", "runtime_differential_traces"),
        _runtime_evidence_from_behavior(behavior_value),
    )
    gui_value = _evidence_value(
        gui_matches,
        base.get("gui_matches"),
        base.get("gui_validation"),
        _nested(base, "equivalence_evidence", "gui_matches"),
        _domain_evidence_from_behavior(behavior_value, "gui"),
    )
    protocol_value = _evidence_value(
        protocol_matches,
        base.get("protocol_matches"),
        base.get("protocol_validation"),
        _nested(base, "equivalence_evidence", "protocol_matches"),
        _domain_evidence_from_behavior(behavior_value, "protocol"),
    )
    overall_provenance = _provenance_refs(
        provenance,
        base.get("provenance"),
        _nested(base, "equivalence_evidence", "provenance"),
    )

    entities = _semantic_entities(semantic_value)
    entity_index = {str(item["id"]): item for item in entities}
    project_scope = _project_scope_entity(semantic_value, project_value, entities)

    dimensions: dict[str, dict[str, Any]] = {}
    mismatches: list[dict[str, Any]] = []

    dimension, found = _assess_static_structure(
        entities,
        project_value,
        float(normalized_thresholds["static_structure_coverage"]),
        project_scope,
    )
    dimensions["static_structure_coverage"] = dimension
    mismatches.extend(found)

    dimension, found = _assess_function_bodies(
        entities,
        project_value,
        body_value,
        float(normalized_thresholds["function_body_recovery"]),
        project_scope,
    )
    dimensions["function_body_recovery"] = dimension
    mismatches.extend(found)

    dimension, found = _assess_compilation(
        compile_value,
        float(normalized_thresholds["compile_result"]),
        project_scope,
    )
    dimensions["compile_result"] = dimension
    mismatches.extend(found)

    comparison_inputs = (
        (
            "runtime_differential_traces",
            runtime_value,
            int(normalized_thresholds["minimum_runtime_trace_count"]),
        ),
        ("gui_matches", gui_value, int(normalized_thresholds["minimum_gui_match_count"])),
        (
            "protocol_matches",
            protocol_value,
            int(normalized_thresholds["minimum_protocol_match_count"]),
        ),
        (
            "behavior_matches",
            behavior_value,
            int(normalized_thresholds["minimum_behavior_match_count"]),
        ),
    )
    for name, value, minimum_count in comparison_inputs:
        dimension, found = _assess_comparisons(
            name,
            value,
            float(normalized_thresholds[name]),
            minimum_count,
            entity_index,
            project_scope,
        )
        dimensions[name] = dimension
        mismatches.extend(found)

    reconstruction_form = _reconstruction_form(base, project_value, body_value, skeleton)
    required_dimensions = [
        item for item in EQUIVALENCE_DIMENSIONS if dimensions[item]["required"] is True
    ]
    overall_score = _overall_score(dimensions, required_dimensions)
    status = _overall_status(
        dimensions,
        required_dimensions,
        mismatches,
        reconstruction_form,
        overall_score,
        float(normalized_thresholds["overall_score"]),
    )
    observed_evidence_matched = status == "matched"
    recommendations = _build_recommendations(
        dimensions,
        mismatches,
        reconstruction_form,
        entities,
    )
    dimension_scores = {
        name: dimensions[name]["score"] for name in EQUIVALENCE_DIMENSIONS
    }
    evidence_index = _build_evidence_index(
        {
            "static_structure_coverage": semantic_value,
            "function_body_recovery": body_value,
            "compile_result": compile_value,
            "runtime_differential_traces": runtime_value,
            "gui_matches": gui_value,
            "protocol_matches": protocol_value,
            "behavior_matches": behavior_value,
        }
    )

    return {
        "schema_version": EQUIVALENCE_ASSESSMENT_SCHEMA_VERSION,
        "assessment_type": "evidence_bounded_source_equivalence",
        "status": status,
        "observed_evidence_matched": observed_evidence_matched,
        "validated": False,
        "validated_within_observed_scope": observed_evidence_matched,
        "claim_scope": "observed_evidence_only",
        "complete_behavior_equivalence_proven": False,
        "perfect_equivalence_claimed": False,
        "score": overall_score,
        "dimension_scores": dimension_scores,
        "thresholds": normalized_thresholds,
        "required_dimensions": required_dimensions,
        "reconstruction_form": reconstruction_form,
        "dimensions": dimensions,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "recommendation_count": len(recommendations),
        "recommendations": recommendations,
        "semantic_ir": {
            "entity_count": len(entities),
            "entity_ids": [str(item["id"]) for item in entities],
            "project_entity": _public_entity(project_scope),
        },
        "evidence": evidence_index,
        "provenance": {
            "assessor": {
                "name": "reverse_analyzer.source.equivalence",
                "version": _ASSESSOR_VERSION,
                "offline": True,
                "claim_scope": "observed_evidence_only",
                "complete_behavior_equivalence_proven": False,
                "perfect_equivalence_claimed": False,
            },
            "source_refs": overall_provenance,
        },
        "limitations": [
            "Matched means that concrete observations met configured thresholds within the observed scope.",
            "The assessment does not prove perfect source, timing, environment, or state-space equivalence.",
            "Compilation and reconstructed-only runtime checks cannot substitute for differential observations.",
        ],
    }


def _assess_static_structure(
    entities: Sequence[Mapping[str, Any]],
    project: Mapping[str, Any] | None,
    threshold: float,
    project_scope: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    expected = [item for item in entities if _kind(item.get("kind")) in _STRUCTURE_KINDS]
    symbols = _project_symbols(project)
    if not expected:
        return (
            _dimension(
                status="unverified",
                score=None,
                threshold=threshold,
                reason="semantic IR contains no structural entities to cover",
                expected_count=0,
                observed_count=len(symbols),
            ),
            [],
        )

    matched = 0
    provenance: list[str] = []
    mismatches: list[dict[str, Any]] = []
    for entity in expected:
        symbol = _matching_symbol(entity, symbols)
        entity_refs = _provenance_refs(entity.get("provenance"))
        if symbol is None:
            mismatches.append(
                _mismatch(
                    "static_structure_coverage",
                    "missing_structural_entity",
                    f"Reconstructed structure is missing {entity['kind']} {entity['name']}",
                    entity,
                    entity_refs,
                    expected={"present": True, "kind": entity["kind"], "name": entity["name"]},
                    actual={"present": False},
                    ordinal=len(mismatches) + 1,
                )
            )
            continue
        symbol_refs = _provenance_refs(symbol.get("provenance"), symbol.get("sources"))
        if not symbol_refs:
            mismatches.append(
                _mismatch(
                    "static_structure_coverage",
                    "structural_entity_without_provenance",
                    f"Reconstructed structure for {entity['name']} has no provenance",
                    entity,
                    entity_refs,
                    expected={"provenance": "non-empty"},
                    actual={"provenance": []},
                    ordinal=len(mismatches) + 1,
                )
            )
            continue
        matched += 1
        provenance.extend(entity_refs)
        provenance.extend(symbol_refs)

    score = _ratio(matched, len(expected))
    if mismatches:
        status = "mismatch"
        reason = "one or more semantic IR structures are missing or untraceable"
    elif score >= threshold and provenance:
        status = "matched"
        reason = "all structural entities met the configured coverage threshold"
    else:
        status = "unverified"
        reason = "structural coverage or provenance is below the configured threshold"
    return (
        _dimension(
            status=status,
            score=score,
            threshold=threshold,
            reason=reason,
            provenance=provenance,
            semantic_ir_entity_ids=[str(item["id"]) for item in expected],
            expected_count=len(expected),
            observed_count=len(symbols),
            matched_count=matched,
            mismatched_count=len(mismatches),
            coverage=score,
        ),
        mismatches,
    )


def _assess_function_bodies(
    entities: Sequence[Mapping[str, Any]],
    project: Mapping[str, Any] | None,
    body_recovery: Mapping[str, Any] | None,
    threshold: float,
    project_scope: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    expected = [item for item in entities if _kind(item.get("kind")) in _FUNCTION_KINDS]
    symbols = _project_symbols(project)
    reports = _mapping_items(body_recovery.get("functions")) if body_recovery else []
    if not expected and reports:
        expected = [_entity_from_report(item, index) for index, item in enumerate(reports, start=1)]
    if not expected:
        return (
            _dimension(
                status="unverified",
                score=None,
                threshold=threshold,
                reason="no semantic IR functions are available for body recovery assessment",
                expected_count=0,
                observed_count=len(reports),
            ),
            [],
        )
    if body_recovery is None:
        return (
            _dimension(
                status="unverified",
                score=None,
                threshold=threshold,
                reason="function body recovery evidence is missing",
                semantic_ir_entity_ids=[str(item["id"]) for item in expected],
                expected_count=len(expected),
                observed_count=0,
            ),
            [],
        )

    recovered = 0
    mismatches: list[dict[str, Any]] = []
    provenance: list[str] = []
    for entity in expected:
        symbol = _matching_symbol(entity, symbols)
        report = _matching_report(entity, symbol, reports)
        status = _status_text(report.get("status")) if report else None
        placeholder = symbol.get("placeholder") if symbol else None
        is_recovered = status in {"recovered", "matched", "passed"} and placeholder is not True
        recovery_refs = _provenance_refs(
            symbol.get("provenance") if symbol else None,
            symbol.get("sources") if symbol else None,
            report.get("provenance") if report else None,
            report.get("sources") if report else None,
            report.get("artifact") if report else None,
        )
        refs = _provenance_refs(entity.get("provenance"), recovery_refs)
        if is_recovered and recovery_refs:
            recovered += 1
            provenance.extend(recovery_refs)
            continue
        reason = status or ("placeholder" if placeholder is True else "missing")
        mismatches.append(
            _mismatch(
                "function_body_recovery",
                "function_body_not_recovered",
                f"Function body for {entity['name']} is not evidence-backed and recovered",
                entity,
                refs or _provenance_refs(entity.get("provenance")),
                expected={"status": "recovered", "placeholder": False},
                actual={"status": reason, "placeholder": placeholder},
                ordinal=len(mismatches) + 1,
            )
        )

    score = _ratio(recovered, len(expected))
    if mismatches:
        status = "mismatch"
        reason = "one or more expected function bodies remain placeholders or unresolved"
    elif score >= threshold and provenance:
        status = "matched"
        reason = "function body recovery met the configured threshold"
    else:
        status = "unverified"
        reason = "function body coverage or provenance is below the configured threshold"
    return (
        _dimension(
            status=status,
            score=score,
            threshold=threshold,
            reason=reason,
            provenance=provenance,
            semantic_ir_entity_ids=[str(item["id"]) for item in expected],
            expected_count=len(expected),
            observed_count=len(reports),
            matched_count=recovered,
            mismatched_count=len(mismatches),
            placeholder_count=max(0, len(expected) - recovered),
            coverage=score,
        ),
        mismatches,
    )


def _assess_compilation(
    compilation: Mapping[str, Any] | None,
    threshold: float,
    project_scope: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if compilation is None:
        return (
            _dimension(
                status="unverified",
                score=None,
                threshold=threshold,
                reason="compile evidence is missing",
            ),
            [],
        )
    status_value = _status_text(compilation.get("status"))
    provenance = _provenance_refs(compilation.get("provenance"), compilation.get("artifact"))
    validated_files = _text_items(compilation.get("validated_files"))
    observed_count = max(
        len(validated_files),
        _non_negative_int(compilation.get("compiled_file_count")),
        _non_negative_int(compilation.get("input_count")),
    )
    score = _score_value(compilation.get("score"))
    if score is None:
        score = 1.0 if status_value in _MATCHED_STATUSES else 0.0
    exit_code_present = "exit_code" in compilation and compilation.get("exit_code") is not None
    exit_code = compilation.get("exit_code")
    exit_code_valid = isinstance(exit_code, int) and not isinstance(exit_code, bool)
    exit_code_conflict = (
        status_value in _MATCHED_STATUSES
        and exit_code_present
        and exit_code_valid
        and exit_code != 0
    )
    if status_value in _MISMATCH_STATUSES or exit_code_conflict:
        mismatch_kind = (
            "compilation_exit_code_mismatch"
            if exit_code_conflict
            else "compilation_failed"
        )
        mismatch = _mismatch(
            "compile_result",
            mismatch_kind,
            "The reconstructed project did not compile successfully",
            project_scope,
            provenance,
            expected={"status": "passed", "exit_code": 0},
            actual={
                "status": status_value,
                "exit_code": compilation.get("exit_code"),
                "diagnostics": _text_items(compilation.get("diagnostics"))[:20],
            },
            ordinal=1,
        )
        return (
            _dimension(
                status="mismatch",
                score=0.0 if exit_code_conflict else score,
                threshold=threshold,
                reason=(
                    "compiler status conflicts with its non-zero exit code"
                    if exit_code_conflict
                    else "compiler evidence reports a failure"
                ),
                provenance=provenance,
                semantic_ir_entity_ids=[str(project_scope["id"])],
                expected_count=max(1, observed_count),
                observed_count=observed_count,
                matched_count=0,
                mismatched_count=1,
                level=_text(compilation.get("level")),
                toolchain=_text(compilation.get("toolchain")),
                exit_code=exit_code,
            ),
            [mismatch],
        )
    if status_value in _UNAVAILABLE_STATUSES:
        return (
            _dimension(
                status="unavailable",
                score=None,
                threshold=threshold,
                reason="the configured compiler or syntax checker is unavailable",
                provenance=provenance,
                semantic_ir_entity_ids=[str(project_scope["id"])],
                observed_count=observed_count,
                level=_text(compilation.get("level")),
                toolchain=_text(compilation.get("toolchain")),
            ),
            [],
        )
    if (
        status_value in _MATCHED_STATUSES
        and observed_count > 0
        and score >= threshold
        and provenance
        and (
            not exit_code_present
            or (exit_code_valid and exit_code == 0)
        )
    ):
        result_status = "matched"
        reason = "compile evidence met the configured threshold"
    else:
        result_status = "unverified"
        reason = "compile evidence lacks covered files, provenance, or threshold score"
    return (
        _dimension(
            status=result_status,
            score=score,
            threshold=threshold,
            reason=reason,
            provenance=provenance,
            semantic_ir_entity_ids=[str(project_scope["id"])],
            expected_count=max(1, observed_count),
            observed_count=observed_count,
            matched_count=observed_count if result_status == "matched" else 0,
            mismatched_count=0,
            level=_text(compilation.get("level")),
            toolchain=_text(compilation.get("toolchain")),
            exit_code=exit_code,
        ),
        [],
    )


def _assess_comparisons(
    name: str,
    evidence: Mapping[str, Any] | Sequence[Any] | None,
    threshold: float,
    minimum_count: int,
    entity_index: Mapping[str, Mapping[str, Any]],
    project_scope: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if evidence is None:
        return (
            _dimension(
                status="unverified",
                score=None,
                threshold=threshold,
                reason=f"{name} evidence is missing",
                minimum_evidence_count=minimum_count,
            ),
            [],
        )
    mapping = evidence if isinstance(evidence, Mapping) else {}
    parent_provenance = _provenance_refs(mapping.get("provenance"), mapping.get("artifact"))
    if isinstance(mapping, Mapping) and mapping.get("applicable") is False:
        reason = _text(mapping.get("reason"))
        if reason and parent_provenance:
            return (
                _dimension(
                    status="not_applicable",
                    score=None,
                    threshold=threshold,
                    reason=reason,
                    required=False,
                    provenance=parent_provenance,
                    minimum_evidence_count=minimum_count,
                ),
                [],
            )
        return (
            _dimension(
                status="unverified",
                score=None,
                threshold=threshold,
                reason="not-applicable scope decision lacks reason or provenance",
                provenance=parent_provenance,
                minimum_evidence_count=minimum_count,
            ),
            [],
        )

    items = _comparison_items(evidence)
    raw_summary = mapping.get("summary")
    summary = raw_summary if isinstance(raw_summary, Mapping) else {}
    summary_shape_valid = raw_summary is None or isinstance(raw_summary, Mapping)
    explicit_status = _status_text(mapping.get("status"))
    if explicit_status in _UNAVAILABLE_STATUSES:
        return (
            _dimension(
                status="unavailable",
                score=None,
                threshold=threshold,
                reason=f"{name} evidence source is unavailable",
                provenance=parent_provenance,
                minimum_evidence_count=minimum_count,
            ),
            [],
        )

    item_results = [_comparison_match(item) for item in items]
    matched_items = [item for item, matched in zip(items, item_results) if matched is True]
    mismatched_items = [item for item, matched in zip(items, item_results) if matched is False]
    unknown_items = [item for item, matched in zip(items, item_results) if matched is None]
    observation_count = len(items)
    total_report = _reported_count_contract(
        observation_count,
        (summary, ("comparison_count", "trace_count", "match_count", "total_count")),
        (mapping, ("total_count",)),
    )
    matched_report = _reported_count_contract(
        len(matched_items),
        (summary, ("matched_comparison_count", "matched_trace_count", "matched_count")),
        (mapping, ("matched_count",)),
    )
    mismatched_report = _reported_count_contract(
        len(mismatched_items),
        (
            summary,
            (
                "mismatched_comparison_count",
                "mismatched_trace_count",
                "mismatched_count",
                "failed_count",
            ),
        ),
        (mapping, ("mismatched_count",)),
    )
    reported_total_count = total_report["reported_count"]
    reported_matched_count = matched_report["reported_count"]
    reported_mismatched_count = mismatched_report["reported_count"]
    score = _ratio(len(matched_items), observation_count) if observation_count else None
    summary_consistent = (
        summary_shape_valid
        and total_report["consistent"]
        and matched_report["consistent"]
        and mismatched_report["consistent"]
    )
    item_provenance = [
        _provenance_refs(item.get("provenance"), item.get("sources"), item.get("artifact"))
        for item in items
    ]
    provenance_complete = bool(parent_provenance) or (
        bool(items) and all(item_provenance)
    )
    dimension_provenance = _provenance_refs(parent_provenance, item_provenance)

    mismatches: list[dict[str, Any]] = []
    for item in mismatched_items:
        entity = _comparison_entity(item, entity_index, project_scope)
        item_name = _text(item.get("name"), item.get("id"), item.get("kind")) or "observation"
        mismatches.append(
            _mismatch(
                name,
                f"{name}_mismatch",
                f"{name} differs for {item_name}",
                entity,
                _provenance_refs(
                    parent_provenance,
                    item.get("provenance"),
                    item.get("sources"),
                    item.get("artifact"),
                ),
                expected=item.get("expected", item.get("original", {"matched": True})),
                actual=item.get("actual", item.get("reconstructed", {"matched": False})),
                ordinal=len(mismatches) + 1,
                observation_id=_text(item.get("id"), item.get("name")),
            )
        )
    aggregate_mismatch_reported = (
        reported_mismatched_count > 0
        and mismatched_report["fields_valid"]
        and mismatched_report["aliases_consistent"]
    )
    if (explicit_status in _MISMATCH_STATUSES or aggregate_mismatch_reported) and not mismatches:
        mismatches.append(
            _mismatch(
                name,
                f"{name}_mismatch",
                f"{name} aggregate evidence reports a difference",
                project_scope,
                parent_provenance,
                expected={"mismatched_count": 0},
                actual={"mismatched_count": max(1, reported_mismatched_count)},
                ordinal=1,
            )
        )

    if mismatches:
        result_status = "mismatch"
        reason = f"{name} contains one or more observed differences"
    elif (
        observation_count >= minimum_count
        and not unknown_items
        and len(matched_items) == observation_count
        and summary_consistent
        and score is not None
        and score >= threshold
        and provenance_complete
        and (
            explicit_status in _MATCHED_STATUSES
            or len(matched_items) == observation_count
        )
    ):
        result_status = "matched"
        reason = f"{name} met the configured score and evidence-count thresholds"
    else:
        result_status = "unverified"
        reason = f"{name} lacks complete observations, provenance, or threshold coverage"

    entity_ids = _comparison_entity_ids(items, entity_index, project_scope)
    return (
        _dimension(
            status=result_status,
            score=score,
            threshold=threshold,
            reason=reason,
            provenance=dimension_provenance,
            semantic_ir_entity_ids=entity_ids,
            expected_count=max(minimum_count, reported_total_count, observation_count),
            observed_count=observation_count,
            matched_count=len(matched_items),
            mismatched_count=max(reported_mismatched_count, len(mismatches)),
            unverified_count=len(unknown_items),
            reported_total_count=reported_total_count,
            reported_matched_count=reported_matched_count,
            reported_mismatched_count=reported_mismatched_count,
            summary_consistent=summary_consistent,
            reported_total_field_count=total_report["field_count"],
            reported_matched_field_count=matched_report["field_count"],
            reported_mismatched_field_count=mismatched_report["field_count"],
            provenance_complete=provenance_complete,
            minimum_evidence_count=minimum_count,
        ),
        mismatches,
    )


def _dimension(
    *,
    status: str,
    score: float | None,
    threshold: float,
    reason: str,
    required: bool = True,
    provenance: Sequence[Any] = (),
    semantic_ir_entity_ids: Sequence[Any] = (),
    **counts: Any,
) -> dict[str, Any]:
    result = {
        "status": status,
        "required": required,
        "score": round(score, 4) if score is not None else None,
        "threshold": round(threshold, 4),
        "meets_threshold": bool(score is not None and score >= threshold),
        "reason": reason,
        "provenance": _provenance_refs(provenance),
        "semantic_ir_entity_ids": _unique_text(semantic_ir_entity_ids),
    }
    result.update({str(key): _json_value(value) for key, value in counts.items()})
    return result


def _mismatch(
    dimension: str,
    kind: str,
    summary: str,
    entity: Mapping[str, Any],
    provenance: Sequence[Any],
    *,
    expected: Any,
    actual: Any,
    ordinal: int,
    observation_id: str | None = None,
) -> dict[str, Any]:
    public_entity = _public_entity(entity)
    refs = _provenance_refs(provenance)
    resolved = bool(refs) and public_entity.get("resolved") is True
    result = {
        "id": f"mismatch:{dimension}:{ordinal:03d}",
        "dimension": dimension,
        "kind": kind,
        "severity": "blocking",
        "summary": _text(summary) or kind,
        "expected": _json_value(expected),
        "actual": _json_value(actual),
        "provenance": refs or [f"unresolved:{dimension}"],
        "provenance_resolved": bool(refs),
        "semantic_ir_entity": public_entity,
        "semantic_ir_entity_ids": [str(public_entity["id"])],
        "association_resolved": resolved,
    }
    if observation_id:
        result["observation_id"] = observation_id
    return result


def _overall_status(
    dimensions: Mapping[str, Mapping[str, Any]],
    required_dimensions: Sequence[str],
    mismatches: Sequence[Mapping[str, Any]],
    reconstruction_form: Mapping[str, Any],
    score: float,
    threshold: float,
) -> str:
    statuses = [str(dimensions[name].get("status")) for name in required_dimensions]
    if mismatches or "mismatch" in statuses:
        return "mismatch"
    if reconstruction_form.get("status") != "recovered" or "unverified" in statuses:
        return "unverified"
    if "unavailable" in statuses:
        return "unavailable"
    if statuses and all(status == "matched" for status in statuses) and score >= threshold:
        return "matched"
    return "unverified"


def _overall_score(
    dimensions: Mapping[str, Mapping[str, Any]], required_dimensions: Sequence[str]
) -> float:
    if not required_dimensions:
        return 0.0
    values = []
    for name in required_dimensions:
        value = dimensions[name].get("score")
        values.append(float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0)
    return round(sum(values) / len(values), 4)


def _reconstruction_form(
    base: Mapping[str, Any],
    project: Mapping[str, Any] | None,
    body_recovery: Mapping[str, Any] | None,
    explicit: bool | None,
) -> dict[str, Any]:
    symbols = _project_symbols(project)
    symbol_placeholders = sum(1 for item in symbols if item.get("placeholder") is True)
    body_placeholders = (
        _non_negative_int(body_recovery.get("placeholder_count")) if body_recovery else 0
    )
    candidates = [
        explicit,
        base.get("skeleton"),
        base.get("stub_only"),
        project.get("placeholder") if project else None,
    ]
    has_skeleton = any(value is True for value in candidates) or symbol_placeholders > 0 or body_placeholders > 0
    explicit_absence = explicit is False or (
        project is not None
        and project.get("placeholder") is False
        and body_placeholders == 0
        and symbol_placeholders == 0
    )
    if has_skeleton:
        status = "skeleton"
        reason = "placeholder or stub evidence is present"
    elif explicit_absence:
        status = "recovered"
        reason = "evidence explicitly reports no remaining skeleton placeholders"
    else:
        status = "unknown"
        reason = "absence of skeleton placeholders has not been demonstrated"
    return {
        "status": status,
        "blocks_validation": status != "recovered",
        "placeholder_count": max(symbol_placeholders, body_placeholders),
        "reason": reason,
    }


def _build_recommendations(
    dimensions: Mapping[str, Mapping[str, Any]],
    mismatches: Sequence[Mapping[str, Any]],
    reconstruction_form: Mapping[str, Any],
    entities: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    actions = {
        "static_structure_coverage": "Map every expected semantic IR structure to a reconstructed symbol with provenance.",
        "function_body_recovery": "Recover unresolved function bodies from bounded decompiler artifacts and retain line provenance.",
        "compile_result": "Run the offline compiler or syntax checker over every reconstructed source file and retain its report.",
        "runtime_differential_traces": "Run original and reconstructed targets with identical inputs and compare normalized runtime traces.",
        "gui_matches": "Compare GUI trees, control properties, event transitions, and rendered-state observations.",
        "protocol_matches": "Compare protocol frames, field values, ordering, errors, and state transitions.",
        "behavior_matches": "Compare declared outputs, side effects, exit states, and normalized streams for both targets.",
    }
    recommendations: list[dict[str, Any]] = []
    for name in EQUIVALENCE_DIMENSIONS:
        dimension = dimensions[name]
        if dimension.get("status") in {"matched", "not_applicable"}:
            continue
        related = [item for item in mismatches if item.get("dimension") == name]
        entity_ids = _unique_text(
            entity_id
            for item in related
            for entity_id in item.get("semantic_ir_entity_ids", [])
        )
        if not entity_ids:
            entity_ids = _unique_text(dimension.get("semantic_ir_entity_ids"))
        recommendations.append(
            {
                "id": f"recommendation:{name}",
                "dimension": name,
                "priority": "high" if related else "medium",
                "action": actions[name],
                "reason": dimension.get("reason"),
                "mismatch_ids": [str(item["id"]) for item in related],
                "semantic_ir_entity_ids": entity_ids,
                "provenance": _provenance_refs(dimension.get("provenance")),
            }
        )
    if reconstruction_form.get("status") != "recovered":
        recommendations.append(
            {
                "id": "recommendation:remove-skeleton-gate",
                "dimension": "reconstruction_form",
                "priority": "high",
                "action": "Replace all skeleton placeholders with evidence-backed implementations before requesting validation.",
                "reason": reconstruction_form.get("reason"),
                "mismatch_ids": [
                    str(item["id"])
                    for item in mismatches
                    if item.get("dimension") == "function_body_recovery"
                ],
                "semantic_ir_entity_ids": [str(item["id"]) for item in entities[:_MAX_ITEMS]],
                "provenance": [],
            }
        )
    return recommendations


def _project_symbols(project: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    if not project:
        return []
    return _mapping_items(project.get("symbols"))


def _semantic_entities(value: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if not value:
        return []
    entities = []
    for index, raw in enumerate(_mapping_items(value.get("entities")), start=1):
        entity_id = _text(raw.get("id")) or f"semantic-ir:entity:{index}"
        kind = _kind(raw.get("kind"), raw.get("type"), raw.get("entity_type")) or "unknown"
        name = _text(raw.get("name"), raw.get("label"), raw.get("symbol"), entity_id) or entity_id
        refs = _provenance_refs(raw.get("provenance"), raw.get("sources"))
        if not refs:
            refs = [f"semantic_ir.entities:{entity_id}"]
        entities.append(
            {
                "id": entity_id,
                "kind": kind,
                "name": name,
                "provenance": refs,
                "resolved": True,
                "address": _text(raw.get("address"), raw.get("entry"), raw.get("offset")),
                "signature": _text(raw.get("signature"), raw.get("prototype")),
            }
        )
    return entities


def _project_scope_entity(
    semantic_ir: Mapping[str, Any] | None,
    project: Mapping[str, Any] | None,
    entities: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    semantic_id = _text(semantic_ir.get("id")) if semantic_ir else None
    project_name = _text(project.get("name")) if project else None
    refs = _provenance_refs(
        semantic_ir.get("provenance") if semantic_ir else None,
        semantic_ir.get("sources") if semantic_ir else None,
        project.get("provenance") if project else None,
    )
    return {
        "id": semantic_id or "semantic-ir:project-scope",
        "kind": "project",
        "name": project_name or "reconstructed_project",
        "provenance": refs,
        "resolved": bool(semantic_id or entities),
    }


def _entity_from_report(report: Mapping[str, Any], index: int) -> dict[str, Any]:
    entity_id = _text(report.get("entity_id"), report.get("semantic_ir_entity_id"))
    name = _text(report.get("name")) or f"function_{index}"
    return {
        "id": entity_id or f"semantic-ir:body-report:{index}",
        "kind": _kind(report.get("kind")) or "function",
        "name": name,
        "provenance": _provenance_refs(report.get("provenance"), report.get("artifact")),
        "resolved": bool(entity_id),
        "address": _text(report.get("address")),
        "signature": _text(report.get("signature")),
    }


def _matching_symbol(
    entity: Mapping[str, Any], symbols: Sequence[Mapping[str, Any]]
) -> Mapping[str, Any] | None:
    entity_id = str(entity.get("id") or "")
    if entity_id:
        matches = [item for item in symbols if str(item.get("entity_id") or "") == entity_id]
        if len(matches) == 1:
            return matches[0]
    address = _text(entity.get("address"))
    if address:
        matches = [item for item in symbols if _text(item.get("address")) == address]
        if len(matches) == 1:
            return matches[0]
    name_key = _name_key(entity.get("name"))
    kind = _kind(entity.get("kind"))
    matches = [
        item
        for item in symbols
        if _name_key(item.get("name"), item.get("identifier")) == name_key
        and _compatible_kind(kind, _kind(item.get("kind")))
    ]
    return matches[0] if len(matches) == 1 else None


def _matching_report(
    entity: Mapping[str, Any],
    symbol: Mapping[str, Any] | None,
    reports: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    nested = symbol.get("body_recovery") if symbol else None
    if isinstance(nested, Mapping):
        return nested
    entity_id = str(entity.get("id") or "")
    if entity_id:
        matches = [
            item
            for item in reports
            if str(item.get("entity_id") or item.get("semantic_ir_entity_id") or "") == entity_id
        ]
        if len(matches) == 1:
            return matches[0]
    address = _text(entity.get("address"))
    if address:
        matches = [item for item in reports if _text(item.get("address")) == address]
        if len(matches) == 1:
            return matches[0]
    name_key = _name_key(entity.get("name"))
    matches = [item for item in reports if _name_key(item.get("name")) == name_key]
    return matches[0] if len(matches) == 1 else None


def _comparison_items(value: Mapping[str, Any] | Sequence[Any]) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        for key in ("traces", "comparisons", "matches", "observations", "items"):
            items = value.get(key)
            if isinstance(items, Sequence) and not isinstance(items, (str, bytes, bytearray)):
                return [item for item in items[:_MAX_ITEMS] if isinstance(item, Mapping)]
        return []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [item for item in value[:_MAX_ITEMS] if isinstance(item, Mapping)]
    return []


def _comparison_match(item: Mapping[str, Any]) -> bool | None:
    signals: list[bool] = []
    for key in ("matched", "match", "equal", "passed"):
        if isinstance(item.get(key), bool):
            signals.append(bool(item[key]))
    status = _status_text(item.get("status"))
    if status in _MATCHED_STATUSES:
        signals.append(True)
    elif status in _MISMATCH_STATUSES:
        signals.append(False)
    return signals[0] if signals and all(value is signals[0] for value in signals) else None


def _comparison_entity(
    item: Mapping[str, Any],
    entity_index: Mapping[str, Mapping[str, Any]],
    project_scope: Mapping[str, Any],
) -> Mapping[str, Any]:
    embedded = item.get("semantic_ir_entity")
    if isinstance(embedded, Mapping):
        entity_id = _text(embedded.get("id")) or "semantic-ir:unresolved"
        return {
            "id": entity_id,
            "kind": _kind(embedded.get("kind")) or "unknown",
            "name": _text(embedded.get("name"), entity_id) or entity_id,
            "provenance": _provenance_refs(embedded.get("provenance"), embedded.get("sources")),
            "resolved": entity_id in entity_index,
        }
    entity_id = _text(
        item.get("semantic_ir_entity_id"),
        item.get("entity_id"),
        item.get("semantic_entity_id"),
    )
    if entity_id and entity_id in entity_index:
        return entity_index[entity_id]
    if entity_id:
        return {
            "id": entity_id,
            "kind": "unknown",
            "name": entity_id,
            "provenance": [],
            "resolved": False,
        }
    return project_scope


def _comparison_entity_ids(
    items: Sequence[Mapping[str, Any]],
    entity_index: Mapping[str, Mapping[str, Any]],
    project_scope: Mapping[str, Any],
) -> list[str]:
    if not items:
        return [str(project_scope["id"])]
    return _unique_text(
        str(_comparison_entity(item, entity_index, project_scope)["id"]) for item in items
    )


def _runtime_evidence_from_behavior(value: Any) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    comparisons = value.get("comparisons")
    runs = value.get("runs")
    if not isinstance(comparisons, list) or not isinstance(runs, Mapping):
        return None
    if not all(isinstance(runs.get(role), Mapping) for role in ("original", "reconstructed")):
        return None
    return {
        "status": value.get("status"),
        "traces": comparisons,
        "summary": value.get("summary"),
        "provenance": value.get("provenance"),
        "derived_from": "behavior_validation.runs_and_comparisons",
    }


def _domain_evidence_from_behavior(value: Any, domain: str) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    comparisons = value.get("comparisons")
    if not isinstance(comparisons, list):
        return None
    selected = []
    for item in comparisons:
        if not isinstance(item, Mapping):
            continue
        marker = _text(item.get("domain"), item.get("category"), item.get("kind"), item.get("name"))
        if marker and domain in marker.casefold():
            selected.append(item)
    if not selected:
        return None
    return {
        "status": value.get("status"),
        "comparisons": selected,
        "provenance": value.get("provenance"),
        "derived_from": f"behavior_validation.{domain}_comparisons",
    }


def _compile_evidence_from_runtime(value: Any) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    steps = value.get("steps")
    if not isinstance(steps, list):
        return None
    build_steps = [
        item
        for item in steps
        if isinstance(item, Mapping) and _status_text(item.get("kind")) in {"build", "compile"}
    ]
    if not build_steps:
        return None
    failed = [item for item in build_steps if _status_text(item.get("status")) in _MISMATCH_STATUSES]
    unavailable = [
        item for item in build_steps if _status_text(item.get("status")) in _UNAVAILABLE_STATUSES
    ]
    if failed:
        status = "failed"
    elif unavailable:
        status = "unavailable"
    elif all(_status_text(item.get("status")) in _MATCHED_STATUSES for item in build_steps):
        status = "passed"
    else:
        status = "unverified"
    return {
        "status": status,
        "compiled_file_count": len(build_steps),
        "provenance": value.get("provenance"),
        "diagnostics": value.get("diagnostics"),
        "derived_from": "runtime_validation.build_steps",
    }


def _build_evidence_index(values: Mapping[str, Any]) -> dict[str, Any]:
    return {
        name: {
            "present": value is not None,
            "sha256": _json_digest(value) if value is not None else None,
        }
        for name, value in values.items()
    }


def _normalize_thresholds(value: Mapping[str, Any] | None) -> dict[str, float | int]:
    if value is None:
        return dict(DEFAULT_EQUIVALENCE_THRESHOLDS)
    if not isinstance(value, Mapping):
        raise TypeError("thresholds must be a mapping or None")
    unknown = sorted(str(key) for key in value if key not in DEFAULT_EQUIVALENCE_THRESHOLDS)
    if unknown:
        raise ValueError(f"unknown equivalence thresholds: {', '.join(unknown)}")
    result = dict(DEFAULT_EQUIVALENCE_THRESHOLDS)
    for key, raw in value.items():
        if isinstance(raw, Mapping):
            raw = raw.get("minimum", raw.get("minimum_score", raw.get("value")))
        if key.startswith("minimum_"):
            if not isinstance(raw, int) or isinstance(raw, bool) or raw < 1 or raw > _MAX_ITEMS:
                raise ValueError(f"{key} must be an integer from 1 to {_MAX_ITEMS}")
            result[key] = raw
            continue
        score = _score_value(raw)
        if score is None:
            raise ValueError(f"{key} must be a finite number from 0 to 1")
        result[key] = score
    return result


def _provenance_refs(*values: Any) -> list[str]:
    result: list[str] = []

    def add(value: Any, prefix: str = "") -> None:
        if len(result) >= _MAX_PROVENANCE_REFS or value is None:
            return
        if isinstance(value, str):
            text = value.strip()
            if text:
                result.append(text[:_MAX_TEXT])
            return
        if isinstance(value, Mapping):
            validator = value.get("validator")
            if isinstance(validator, Mapping):
                name = _text(validator.get("name"))
                version = _text(validator.get("version"))
                if name:
                    result.append(f"validator:{name}{('@' + version) if version else ''}")
            for key in ("source", "sources", "path", "artifact", "inputs", "line_provenance"):
                if key in value:
                    add(value.get(key), key)
            for key in ("sha256", "evidence_sha256", "spec_sha256"):
                digest = _text(value.get(key))
                if digest:
                    result.append(f"{key}:{digest}")
            name = _text(value.get("name"))
            if prefix in {"artifact", "source"} and name:
                result.append(f"{prefix}:{name}")
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item in value[:_MAX_PROVENANCE_REFS]:
                add(item, prefix)

    for item in values:
        add(item)
    return _unique_text(result)[:_MAX_PROVENANCE_REFS]


def _public_entity(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": _text(value.get("id")) or "semantic-ir:unresolved",
        "kind": _kind(value.get("kind")) or "unknown",
        "name": _text(value.get("name"), value.get("id")) or "unresolved",
        "resolved": value.get("resolved") is True,
        "provenance": _provenance_refs(value.get("provenance")),
    }


def _reported_count_contract(
    actual_count: int,
    *sources: tuple[Mapping[str, Any], Sequence[str]],
) -> dict[str, Any]:
    values: list[int] = []
    fields_valid = True
    for source, keys in sources:
        for key in keys:
            if key not in source:
                continue
            value = source.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                fields_valid = False
                continue
            values.append(value)
    aliases_consistent = fields_valid and len(set(values)) <= 1
    return {
        "reported_count": max(values, default=0),
        "field_count": len(values),
        "fields_valid": fields_valid,
        "aliases_consistent": aliases_consistent,
        "consistent": fields_valid and aliases_consistent and all(
            value == actual_count for value in values
        ),
    }


def _mapping_items(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [item for item in value[:_MAX_ITEMS] if isinstance(item, Mapping)]


def _mapping_or_none(*values: Any) -> Mapping[str, Any] | None:
    for value in values:
        if isinstance(value, Mapping):
            return value
    return None


def _evidence_value(*values: Any) -> Mapping[str, Any] | Sequence[Any] | None:
    for value in values:
        if isinstance(value, Mapping):
            return value
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return value
    return None


def _nested(value: Mapping[str, Any], *path: str) -> Any:
    current: Any = value
    for item in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(item)
    return current


def _kind(*values: Any) -> str | None:
    text = _text(*values)
    if not text:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "_", text.casefold()).strip("_")
    aliases = {
        "func": "function",
        "proc": "procedure",
        "ui_handler": "handler",
        "event_handler": "handler",
    }
    return aliases.get(normalized, normalized)


def _compatible_kind(left: str | None, right: str | None) -> bool:
    if left == right:
        return True
    return left in _FUNCTION_KINDS and right in _FUNCTION_KINDS


def _name_key(*values: Any) -> str:
    text = _text(*values) or ""
    return re.sub(r"[^a-z0-9]+", "", text.casefold())


def _status_text(value: Any) -> str | None:
    text = _text(value)
    return re.sub(r"[^a-z0-9]+", "_", text.casefold()).strip("_") if text else None


def _text(*values: Any) -> str | None:
    for value in values:
        if value is None or isinstance(value, (Mapping, list, tuple, set)):
            continue
        text = str(value).strip()
        if text:
            return text[:_MAX_TEXT]
    return None


def _text_items(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return _unique_text(item for item in value if isinstance(item, str))


def _unique_text(values: Any) -> list[str]:
    if isinstance(values, str):
        values = [values]
    result: list[str] = []
    seen: set[str] = set()
    try:
        iterator = iter(values)
    except TypeError:
        return result
    for value in iterator:
        text = str(value).strip()
        if not text:
            continue
        key = text.casefold()
        if key not in seen:
            seen.add(key)
            result.append(text[:_MAX_TEXT])
        if len(result) >= _MAX_ITEMS:
            break
    return result


def _non_negative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _score_value(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        return None
    return round(score, 4)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator > 0 else 0.0


def _json_digest(value: Any) -> str:
    serialized = json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _json_value(value: Any, depth: int = 0) -> Any:
    if depth >= 8:
        return _text(value) or type(value).__name__
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, Mapping):
        return {
            str(key)[:_MAX_TEXT]: _json_value(item, depth + 1)
            for key, item in list(value.items())[:_MAX_ITEMS]
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item, depth + 1) for item in value[:_MAX_ITEMS]]
    return _text(value) or type(value).__name__
