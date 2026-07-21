"""Offline dashboard generation for reverse-engineering experiment workspaces."""

from __future__ import annotations

from datetime import datetime, timezone
from functools import partial
import heapq
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Iterable
from urllib.parse import quote

from .acceptance import verify_acceptance_record
from .dashboard_platform_core import (
    build_analysis_views,
    build_capability_audit_view,
    build_platform_core_view,
    build_risk_highlights,
    collect_report_artifacts,
)
from .source_reconstruction import summarize_source_reconstruction


_ENVIRONMENT_REPORT_NAME = "environment-validation.json"
_MAX_ENVIRONMENT_REPORT_BYTES = 2 * 1024 * 1024
_MAX_ENVIRONMENT_REPORT_CANDIDATES = 128
_MAX_ACCEPTANCE_RECORD_BYTES = 2 * 1024 * 1024
_MAX_ACCEPTANCE_RECORDS = 500
_MAX_CAMPAIGN_RESULT_BYTES = 16 * 1024 * 1024
_MAX_CAMPAIGN_RESULTS = 200
_ENVIRONMENT_CHECK_STATUSES = {"discovered", "verified", "failed", "unavailable"}
_ENVIRONMENT_WORKFLOW_STATUSES = {
    "verified",
    "dependency_gated",
    "partial",
    "failed",
    "unavailable",
    "unsupported_host",
}
_ENVIRONMENT_FIXTURE_STATUSES = {
    "repository_ready",
    "ready_to_run",
    "dependency_gated",
    "unsupported_host",
    "live_verified",
}


def build_dashboard(
    workspace: str | Path,
    *,
    out_dir: str | Path | None = None,
    knowledge_dir: str | Path | None = None,
) -> dict:
    """Build an offline dashboard and return the JSON-compatible dashboard data."""

    root = Path(workspace)
    destination = Path(out_dir) if out_dir is not None else root / "dashboard"
    knowledge_root = (
        Path(knowledge_dir)
        if knowledge_dir is not None
        else root / ".reverse_analyzer" / "knowledge"
    )
    diagnostics: dict[str, Any] = {
        "files_scanned": 0,
        "files_loaded": 0,
        "malformed_json": 0,
        "invalid_records": 0,
        "skipped_files": [],
        "environment_validation": {
            "candidates_seen": 0,
            "candidates_considered": 0,
            "candidate_limit_reached": False,
            "malformed_reports": 0,
            "invalid_reports": 0,
            "oversize_reports": 0,
            "unsafe_paths": 0,
            "skipped_files": [],
        },
        "acceptance_history": {
            "candidates_seen": 0,
            "records_loaded": 0,
            "malformed_records": 0,
            "invalid_records": 0,
            "oversize_records": 0,
            "unsafe_paths": 0,
            "candidate_limit_reached": False,
            "skipped_files": [],
        },
    }

    experiments = _load_records((root / "experiments",), diagnostics)
    sessions = _load_records(_session_directories(root), diagnostics)
    knowledge_stores = {
        "dynamic": _load_json(knowledge_root / "dynamic_profiles.json", diagnostics),
        "gui": _load_json(knowledge_root / "gui_strategies.json", diagnostics),
        "patch": _load_json(knowledge_root / "patch_strategies.json", diagnostics),
        "engine": _load_json(knowledge_root / "engine_strategies.json", diagnostics),
        "protocol": _load_json(knowledge_root / "protocol_formats.json", diagnostics),
        "source": _load_json(knowledge_root / "source_restoration.json", diagnostics),
        "llm_jailbreak": _load_json(
            knowledge_root / "llm_jailbreak_strategies.json",
            diagnostics,
        ),
    }
    knowledge_sessions = _knowledge_session_records(
        _load_json(knowledge_root / "sessions.json", diagnostics),
        diagnostics,
    )
    source_reconstruction = summarize_source_reconstruction(root)
    environment_validation = _load_environment_validation(root, diagnostics)
    acceptance_history = _load_acceptance_history(root, diagnostics)
    binary_patches = _load_binary_patches(root, diagnostics)
    evidence_manifests = _load_evidence_manifests(root, diagnostics)
    reports = _load_reports(root, diagnostics)
    campaign_analytics = _build_campaign_analytics(root, reports, diagnostics)

    experiments.sort(key=_record_timestamp, reverse=True)
    sessions.sort(key=_record_timestamp, reverse=True)
    status_counts: dict[str, int] = {}
    for experiment in experiments:
        status = str(experiment.get("status") or "unknown").lower()
        status_counts[status] = status_counts.get(status, 0) + 1

    capability_audit = build_capability_audit_view(reports)
    analysis_views = build_analysis_views(
        reports,
        source_summary=source_reconstruction,
    )
    knowledge_recommendations = _build_knowledge_recommendations(knowledge_stores)
    session_analytics = _build_session_analytics(sessions, knowledge_sessions)
    risk_highlights = build_risk_highlights(reports, analysis_views)
    platform_report = _latest_platform_report(reports)
    platform_core = build_platform_core_view(
        platform_report,
        capability_audit=capability_audit,
    )
    artifact_references = collect_report_artifacts(reports, capability_audit)
    artifact_references.extend(
        _workspace_artifact_references(
            reports=reports,
            sessions=sessions,
            binary_patches=binary_patches,
            evidence_manifests=evidence_manifests,
            source_reconstruction=source_reconstruction,
            environment_validation=environment_validation,
            acceptance_history=acceptance_history,
        )
    )
    artifact_navigation = _build_artifact_navigation(
        artifact_references,
        workspace=root,
        destination=destination,
    )
    _attach_acceptance_artifact_links(acceptance_history, artifact_navigation)

    data = {
        "generated_at": _utc_now(),
        "summary": {
            "experiment_total": len(experiments),
            "status_counts": status_counts,
            "session_total": len(sessions),
            "completed_total": status_counts.get("completed", 0),
        },
        "experiments": experiments[:50],
        "sessions": sessions[:20],
        "recommendations": {
            "dynamic_profile": knowledge_recommendations["dynamic"]["recommendation"],
            "gui_strategy": knowledge_recommendations["gui"]["recommendation"],
            "patch_strategy": knowledge_recommendations["patch"]["recommendation"],
            "engine_strategy": knowledge_recommendations["engine"]["recommendation"],
            "protocol_format": knowledge_recommendations["protocol"]["recommendation"],
            "source_restoration": knowledge_recommendations["source"]["recommendation"],
            "llm_jailbreak_strategy": knowledge_recommendations["llm_jailbreak"]["recommendation"],
        },
        "knowledge_recommendations": knowledge_recommendations,
        "analysis_views": analysis_views,
        "capability_audit": capability_audit,
        "session_analytics": session_analytics,
        "session_compare": session_analytics["compare"],
        "session_trend": session_analytics["trend"],
        "campaign_analytics": campaign_analytics,
        "risk_highlights": risk_highlights,
        "artifact_navigation": artifact_navigation,
        "source_reconstruction": source_reconstruction,
        "environment_validation": environment_validation,
        "acceptance_history": acceptance_history,
        "binary_patches": binary_patches,
        "evidence_manifests": evidence_manifests,
        "platform_core": platform_core,
        "diagnostics": diagnostics,
    }

    destination.mkdir(parents=True, exist_ok=True)
    _write_json(destination / "data.json", data)
    (destination / "index.html").write_text(_html_document(data), encoding="utf-8")
    return data


def _build_campaign_analytics(
    workspace: Path,
    reports: Iterable[dict[str, Any]],
    diagnostics: dict[str, Any],
) -> dict[str, Any]:
    """Build bounded campaign trees, traces, trends, and comparison rows."""

    campaigns: dict[str, dict[str, Any]] = {}
    candidates: list[Path] = []
    try:
        for path in workspace.rglob("result.json"):
            if not path.is_file():
                continue
            has_campaign_artifacts = (
                (path.parent / "campaign.json").is_file()
                and (path.parent / "attempts.json").is_file()
            )
            in_provider_output = (
                path.parent.name.casefold() == "engine"
                and "llm_jailbreak" in {part.casefold() for part in path.parts}
            )
            if has_campaign_artifacts or in_provider_output:
                candidates.append(path)
    except OSError:
        candidates = []
    candidates.sort(key=_safe_modified_ns, reverse=True)

    state = diagnostics.setdefault(
        "campaign_analytics",
        {
            "candidates_seen": len(candidates),
            "candidates_loaded": 0,
            "candidate_limit_reached": len(candidates) > _MAX_CAMPAIGN_RESULTS,
            "oversize_results": 0,
            "invalid_results": 0,
        },
    )
    for result_path in candidates[:_MAX_CAMPAIGN_RESULTS]:
        try:
            if result_path.stat().st_size > _MAX_CAMPAIGN_RESULT_BYTES:
                state["oversize_results"] += 1
                continue
        except OSError:
            continue
        result = _load_json(result_path, diagnostics)
        if not isinstance(result, dict) or not str(result.get("campaign_id") or "").strip():
            state["invalid_results"] += 1
            continue
        attempts_payload = _load_json(result_path.parent / "attempts.json", diagnostics)
        campaign_payload = _load_json(result_path.parent / "campaign.json", diagnostics)
        attempts = result.get("attempts")
        if not isinstance(attempts, list) and isinstance(attempts_payload, dict):
            attempts = attempts_payload.get("attempts")
        normalized = _campaign_analytics_record(
            result,
            campaign_payload if isinstance(campaign_payload, dict) else {},
            attempts if isinstance(attempts, list) else [],
            source_path=_relative_workspace_path(result_path, workspace),
        )
        campaigns[normalized["campaign_id"]] = normalized
        state["candidates_loaded"] += 1

    # Report summaries keep campaign comparison useful when detailed engine
    # artifacts were not retained in this workspace.
    for entry in reports:
        payload = entry.get("payload")
        section = payload.get("llm_jailbreak_analysis") if isinstance(payload, dict) else None
        if not isinstance(section, dict):
            continue
        campaign_id = str(section.get("campaign_id") or "").strip()
        if not campaign_id or campaign_id in campaigns:
            continue
        campaigns[campaign_id] = _campaign_report_record(section, entry)

    rows = sorted(
        campaigns.values(),
        key=lambda item: (str(item.get("completed_at") or item.get("started_at") or ""), item["campaign_id"]),
        reverse=True,
    )
    total_attempts = sum(int(item.get("attempt_count") or 0) for item in rows)
    total_tokens = sum(int(item.get("total_tokens") or 0) for item in rows)
    total_cost = sum(float(item.get("total_cost_usd") or 0.0) for item in rows)
    successful = sum(1 for item in rows if item.get("success") is True)
    return {
        "campaign_count": len(rows),
        "successful_campaigns": successful,
        "breakthrough_rate": round(successful / len(rows), 6) if rows else 0.0,
        "attempt_count": total_attempts,
        "total_tokens": total_tokens,
        "total_cost_usd": round(total_cost, 8),
        "campaigns": rows,
        "comparison": [_campaign_comparison_row(item) for item in rows],
    }


def _campaign_analytics_record(
    result: dict[str, Any],
    campaign: dict[str, Any],
    attempts: list[Any],
    *,
    source_path: str,
) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    verdicts: list[dict[str, Any]] = []
    trend: list[dict[str, Any]] = []
    cumulative_tokens = 0
    cumulative_cost = 0.0
    cumulative_latency = 0.0
    previous_mode = ""
    previous_strategy = ""
    for index, raw in enumerate(attempts):
        if not isinstance(raw, dict):
            continue
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        response = raw.get("response") if isinstance(raw.get("response"), dict) else {}
        score_payload = raw.get("score") if isinstance(raw.get("score"), dict) else {}
        usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
        attack_mode = str(metadata.get("attack_mode") or "builtin")
        strategy = str(raw.get("strategy") or "unknown")
        candidate_id = str(
            metadata.get("node_id")
            or metadata.get("candidate_id")
            or metadata.get("genome_id")
            or raw.get("mutation_id")
            or raw.get("attempt_id")
            or f"attempt-{index + 1}"
        )
        parent_ids = _campaign_parent_ids(metadata)
        tokens = _campaign_usage_tokens(usage)
        cost = _campaign_attempt_cost(raw, response, usage, metadata)
        latency_ms = max(0.0, 1000.0 * _finite_number(response.get("latency_seconds")))
        score = _finite_number(score_payload.get("score"))
        success = bool(raw.get("success") or metadata.get("final_success"))
        node = {
            "attempt_id": str(raw.get("attempt_id") or f"attempt-{index + 1}"),
            "candidate_id": candidate_id,
            "parent_ids": parent_ids,
            "round_index": int(_finite_number(raw.get("round_index"), index + 1)),
            "depth": int(_finite_number(metadata.get("depth"), len(parent_ids))),
            "attack_mode": attack_mode,
            "strategy": strategy,
            "score": round(score, 6),
            "success": success,
            "latency_ms": round(latency_ms, 3),
            "tokens": tokens,
            "cost_usd": round(cost, 8),
            "error": str(raw.get("error") or ""),
            "started_at": str(raw.get("started_at") or ""),
            "completed_at": str(raw.get("completed_at") or ""),
        }
        nodes.append(node)
        switched = bool(index and (attack_mode != previous_mode or strategy != previous_strategy))
        trace.append(
            {
                "attempt_id": node["attempt_id"],
                "round_index": node["round_index"],
                "attack_mode": attack_mode,
                "strategy": strategy,
                "switched": switched,
                "from_attack_mode": previous_mode if switched else None,
                "from_strategy": previous_strategy if switched else None,
                "optimizer_recommendation": metadata.get("optimizer_recommendation", {}),
            }
        )
        verdict = metadata.get("semantic_judge_verdict")
        if not isinstance(verdict, dict):
            verdict = metadata.get("semantic_judge")
        if isinstance(verdict, dict):
            verdicts.append(
                {
                    "attempt_id": node["attempt_id"],
                    "judge_name": str(verdict.get("judge_name") or "semantic_judge"),
                    "score": round(_finite_number(verdict.get("score")), 6),
                    "success": bool(verdict.get("success")),
                    "refused": bool(verdict.get("refused")),
                    "confidence": round(_finite_number(verdict.get("confidence")), 6),
                    "rationale": str(verdict.get("rationale") or ""),
                }
            )
        cumulative_tokens += tokens
        cumulative_cost += cost
        cumulative_latency += latency_ms
        trend.append(
            {
                "round_index": node["round_index"],
                "score": node["score"],
                "tokens": tokens,
                "cumulative_tokens": cumulative_tokens,
                "cost_usd": node["cost_usd"],
                "cumulative_cost_usd": round(cumulative_cost, 8),
                "latency_ms": node["latency_ms"],
                "cumulative_latency_ms": round(cumulative_latency, 3),
            }
        )
        previous_mode, previous_strategy = attack_mode, strategy

    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    target = campaign.get("target") if isinstance(campaign.get("target"), dict) else {}
    latency_ms = cumulative_latency or 1000.0 * _finite_number(summary.get("latency_seconds"))
    total_tokens = cumulative_tokens or _campaign_usage_tokens(
        summary.get("usage") if isinstance(summary.get("usage"), dict) else {}
    )
    return {
        "campaign_id": str(result.get("campaign_id")),
        "name": str(campaign.get("name") or result.get("campaign_id")),
        "model": str(target.get("model") or "unknown"),
        "status": str(result.get("status") or "unknown"),
        "success": bool(result.get("success")),
        "started_at": str(result.get("started_at") or ""),
        "completed_at": str(result.get("completed_at") or ""),
        "source_path": source_path,
        "detailed": True,
        "resumed": bool(summary.get("resumed")),
        "attempt_count": len(nodes),
        "successful_attempts": sum(1 for node in nodes if node["success"]),
        "best_score": max((node["score"] for node in nodes), default=_finite_number(summary.get("best_score"))),
        "latency_ms": round(latency_ms, 3),
        "total_tokens": total_tokens,
        "total_cost_usd": round(cumulative_cost, 8),
        "judge_mode": str(campaign.get("semantic_judge") or "disabled"),
        "attempt_tree": nodes,
        "strategy_trace": trace,
        "judge_verdicts": verdicts,
        "trend": trend,
    }


def _campaign_report_record(section: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "campaign_id": str(section.get("campaign_id")),
        "name": str(section.get("campaign_id")),
        "model": str(section.get("model") or "unknown"),
        "status": str(section.get("status") or "unknown"),
        "success": bool(section.get("success")),
        "started_at": "",
        "completed_at": str(entry.get("timestamp") or ""),
        "source_path": str(entry.get("source_path") or ""),
        "detailed": False,
        "resumed": bool((section.get("checkpoint") or {}).get("resumed")) if isinstance(section.get("checkpoint"), dict) else False,
        "attempt_count": int(_finite_number(section.get("attempt_count"))),
        "successful_attempts": 1 if section.get("success") else 0,
        "best_score": round(_finite_number(section.get("score")), 6),
        "latency_ms": round(_finite_number(section.get("latency_ms")), 3),
        "total_tokens": int(_finite_number(section.get("total_tokens"))),
        "total_cost_usd": round(_finite_number(section.get("total_cost_usd")), 8),
        "judge_mode": str(section.get("semantic_judge") or "disabled"),
        "attempt_tree": [],
        "strategy_trace": [],
        "judge_verdicts": [],
        "trend": [],
    }


def _campaign_comparison_row(campaign: dict[str, Any]) -> dict[str, Any]:
    attempts = int(campaign.get("attempt_count") or 0)
    return {
        key: campaign.get(key)
        for key in (
            "campaign_id", "name", "model", "status", "success", "attempt_count",
            "successful_attempts", "best_score", "latency_ms", "total_tokens",
            "total_cost_usd", "judge_mode", "resumed", "source_path",
        )
    } | {
        "average_latency_ms": round(float(campaign.get("latency_ms") or 0.0) / attempts, 3) if attempts else 0.0,
        "average_tokens": round(float(campaign.get("total_tokens") or 0.0) / attempts, 3) if attempts else 0.0,
    }


def _campaign_parent_ids(metadata: dict[str, Any]) -> list[str]:
    parents = metadata.get("parents")
    if isinstance(parents, list):
        return [str(item) for item in parents if str(item)]
    parent = metadata.get("parent_id")
    return [str(parent)] if parent not in (None, "") else []


def _campaign_usage_tokens(usage: dict[str, Any]) -> int:
    for key in ("total_tokens", "total_token_count"):
        if key in usage:
            return max(0, int(_finite_number(usage.get(key))))
    input_tokens = max(0, int(_finite_number(usage.get("prompt_tokens", usage.get("input_tokens")))))
    output_tokens = max(0, int(_finite_number(usage.get("completion_tokens", usage.get("output_tokens")))))
    return input_tokens + output_tokens


def _campaign_attempt_cost(*values: dict[str, Any]) -> float:
    for value in values:
        for key in ("cost_usd", "total_cost_usd", "estimated_cost_usd", "cost"):
            if key in value:
                return max(0.0, _finite_number(value.get(key)))
    return 0.0


def _finite_number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _safe_modified_ns(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return 0


def _relative_workspace_path(path: Path, workspace: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except (OSError, ValueError):
        return path.name


def serve_dashboard(
    directory: str | Path, *, host: str = "127.0.0.1", port: int = 0
) -> ThreadingHTTPServer:
    """Create a dashboard HTTP server without entering its serving loop."""

    handler = partial(SimpleHTTPRequestHandler, directory=str(Path(directory)))
    return ThreadingHTTPServer((host, port), handler)



def _load_reports(workspace: Path, diagnostics: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[Path] = []
    try:
        candidates = list(workspace.rglob("report.json"))
    except OSError:
        pass

    def modified(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    candidates.sort(key=lambda path: (modified(path), str(path)), reverse=True)
    reports: list[dict[str, Any]] = []
    for path in candidates:
        payload = _load_json(path, diagnostics)
        if not isinstance(payload, dict):
            if payload is not None:
                diagnostics["invalid_records"] += 1
            continue
        try:
            source_path = path.resolve().relative_to(workspace.resolve()).as_posix()
        except (OSError, ValueError):
            source_path = str(path)
        timestamp = _record_timestamp(payload)
        if not timestamp:
            try:
                timestamp = (
                    datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
            except OSError:
                timestamp = ""
        reports.append(
            {
                "payload": payload,
                "source_path": source_path,
                "timestamp": timestamp,
            }
        )
    return reports


def _latest_platform_report(reports: Iterable[dict[str, Any]]) -> dict[str, Any]:
    for entry in reports:
        payload = entry.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("platform_core"), dict):
            return payload
    return {"platform_core": {"status": "unavailable"}}


def _load_platform_core_report(workspace: Path, diagnostics: dict[str, Any]) -> dict[str, Any]:
    """Compatibility wrapper returning the newest Platform Core report."""

    return _latest_platform_report(_load_reports(workspace, diagnostics))


def _load_environment_validation(
    workspace: Path, diagnostics: dict[str, Any]
) -> dict[str, Any]:
    """Load the newest valid environment report confined to ``workspace``."""

    state = diagnostics.setdefault("environment_validation", {})
    for key, default in {
        "candidates_seen": 0,
        "candidates_considered": 0,
        "candidate_limit_reached": False,
        "malformed_reports": 0,
        "invalid_reports": 0,
        "oversize_reports": 0,
        "unsafe_paths": 0,
        "skipped_files": [],
    }.items():
        state.setdefault(key, default)

    unavailable = {
        "available": False,
        "source_path": None,
        "modified_at": None,
        "checks": {},
        "workflows": {},
        "summary": {},
        "reason": f"No valid {_ENVIRONMENT_REPORT_NAME} found in the workspace.",
    }
    try:
        root = workspace.resolve()
    except (OSError, RuntimeError):
        return unavailable
    if not root.is_dir():
        return unavailable

    candidates: list[tuple[int, str, Path, int]] = []
    seen: set[Path] = set()
    try:
        for candidate in root.rglob(_ENVIRONMENT_REPORT_NAME):
            state["candidates_seen"] += 1
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
                stat = resolved.stat()
            except ValueError:
                state["unsafe_paths"] += 1
                _record_environment_skip(state, candidate, "outside_workspace")
                continue
            except (OSError, RuntimeError) as error:
                _record_environment_skip(state, candidate, f"unreadable: {error}")
                continue
            if not resolved.is_file() or resolved in seen:
                continue
            seen.add(resolved)
            entry = (stat.st_mtime_ns, resolved.as_posix(), resolved, stat.st_size)
            if len(candidates) < _MAX_ENVIRONMENT_REPORT_CANDIDATES:
                heapq.heappush(candidates, entry)
            elif entry > candidates[0]:
                heapq.heapreplace(candidates, entry)
                state["candidate_limit_reached"] = True
            else:
                state["candidate_limit_reached"] = True
    except OSError as error:
        _record_environment_skip(state, root, f"scan_failed: {error}")

    for _, _, path, size in sorted(candidates, reverse=True):
        state["candidates_considered"] += 1
        diagnostics["files_scanned"] += 1
        relative = path.relative_to(root).as_posix()
        if size > _MAX_ENVIRONMENT_REPORT_BYTES:
            state["oversize_reports"] += 1
            _record_environment_skip(state, path, "report_too_large", relative=relative)
            continue
        try:
            with path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            diagnostics["malformed_json"] += 1
            state["malformed_reports"] += 1
            _record_environment_skip(
                state,
                path,
                f"malformed_json: {error}",
                relative=relative,
            )
            continue
        if not _valid_environment_report(value):
            diagnostics["invalid_records"] += 1
            state["invalid_reports"] += 1
            _record_environment_skip(state, path, "invalid_schema", relative=relative)
            continue
        diagnostics["files_loaded"] += 1
        report = dict(value)
        report.update(
            {
                "available": True,
                "source_path": relative,
                "modified_at": _path_modified_at(path),
            }
        )
        return report
    return unavailable


def _record_environment_skip(
    state: dict[str, Any],
    path: Path,
    reason: str,
    *,
    relative: str | None = None,
) -> None:
    skipped = state.setdefault("skipped_files", [])
    if len(skipped) < _MAX_ENVIRONMENT_REPORT_CANDIDATES:
        skipped.append({"path": relative or str(path), "reason": reason})


def _load_acceptance_history(
    workspace: Path, diagnostics: dict[str, Any]
) -> dict[str, Any]:
    """Load bounded acceptance run records confined to the workspace."""

    state = diagnostics.setdefault("acceptance_history", {})
    for key, default in {
        "candidates_seen": 0,
        "records_loaded": 0,
        "malformed_records": 0,
        "invalid_records": 0,
        "oversize_records": 0,
        "unsafe_paths": 0,
        "candidate_limit_reached": False,
        "skipped_files": [],
    }.items():
        state.setdefault(key, default)
    records: list[dict[str, Any]] = []
    try:
        root = workspace.resolve()
    except (OSError, RuntimeError):
        return _acceptance_history_summary(records)
    if not root.is_dir():
        return _acceptance_history_summary(records)

    candidates: list[Path] = []
    try:
        discovered = sorted(root.rglob("acceptance/records/*.json"))
    except OSError as error:
        state["skipped_files"].append({"path": str(root), "reason": str(error)})
        return _acceptance_history_summary(records)
    state["candidates_seen"] = len(discovered)
    if len(discovered) > _MAX_ACCEPTANCE_RECORDS:
        state["candidate_limit_reached"] = True
        discovered = discovered[:_MAX_ACCEPTANCE_RECORDS]

    seen: set[Path] = set()
    for candidate in discovered:
        try:
            path = candidate.resolve(strict=True)
            path.relative_to(root)
            size = path.stat().st_size
        except ValueError:
            state["unsafe_paths"] += 1
            state["skipped_files"].append(
                {"path": str(candidate), "reason": "outside_workspace"}
            )
            continue
        except (OSError, RuntimeError) as error:
            state["skipped_files"].append(
                {"path": str(candidate), "reason": f"unreadable: {error}"}
            )
            continue
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        relative = path.relative_to(root).as_posix()
        if size > _MAX_ACCEPTANCE_RECORD_BYTES:
            state["oversize_records"] += 1
            state["skipped_files"].append(
                {"path": relative, "reason": "record_too_large"}
            )
            continue
        malformed_before = diagnostics["malformed_json"]
        value = _load_json(path, diagnostics)
        if value is None:
            if diagnostics["malformed_json"] > malformed_before:
                state["malformed_records"] += 1
            continue
        if not _valid_acceptance_record(value):
            diagnostics["invalid_records"] += 1
            state["invalid_records"] += 1
            state["skipped_files"].append(
                {"path": relative, "reason": "invalid_schema"}
            )
            continue
        record = dict(value)
        integrity = verify_acceptance_record(path)
        record["declared_live_verified"] = record.get("live_verified") is True
        record["integrity"] = integrity
        record["live_verified"] = integrity.get("live_verified") is True
        record["source_path"] = relative
        record["outcome"] = _acceptance_outcome(record["outcome"])
        record["observed_artifacts"] = _acceptance_observed_artifacts(
            record.get("observed_artifacts")
        )
        if not isinstance(record.get("record_path"), str) or not record["record_path"].strip():
            record["record_path"] = relative
        records.append(record)
        state["records_loaded"] += 1

    records.sort(
        key=lambda item: (
            str(item.get("finished_at") or item.get("started_at") or ""),
            str(item.get("fixture_id") or ""),
        ),
        reverse=True,
    )
    return _acceptance_history_summary(records)


def _valid_acceptance_record(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    for key in ("fixture_id", "capability", "outcome", "started_at", "finished_at"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            return False
    if value.get("phase") not in {"P0", "P1", "P2", "P3", "P4"}:
        return False
    if not isinstance(value.get("live_verified"), bool):
        return False
    record_path = value.get("record_path")
    if record_path is not None and (
        not isinstance(record_path, str) or not record_path.strip()
    ):
        return False
    observed = value.get("observed_artifacts")
    if observed is not None and not isinstance(observed, list):
        return False
    return True


def _acceptance_outcome(value: Any) -> str:
    return str(value or "unknown").strip().casefold().replace("-", "_").replace(" ", "_")


def _acceptance_observed_artifacts(value: Any) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []
    for item in value if isinstance(value, list) else []:
        if isinstance(item, str) and item.strip():
            artifacts.append({"path": item.strip(), "label": Path(item).name or item})
        elif isinstance(item, dict) and isinstance(item.get("path"), str) and item["path"].strip():
            path = item["path"].strip()
            artifacts.append(
                {
                    "path": path,
                    "label": str(item.get("label") or Path(path).name or path),
                    "kind": str(item.get("kind") or "acceptance_artifact"),
                }
            )
    return artifacts


def _acceptance_history_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    failed = {"failed", "failure", "error"}
    blocked = {"dependency_blocked", "dependency_gated", "blocked", "unavailable"}
    return {
        "available": bool(records),
        "summary": {
            "total": len(records),
            "live_verified": sum(item.get("live_verified") is True for item in records),
            "failed": sum(item.get("outcome") in failed for item in records),
            "dependency_blocked": sum(item.get("outcome") in blocked for item in records),
        },
        "records": records,
    }


def _valid_environment_report(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    schema_version = value.get("schema_version")
    if isinstance(schema_version, bool) or schema_version not in {1, 2}:
        return False
    if not isinstance(value.get("generated_at"), str) or not value["generated_at"].strip():
        return False
    if not isinstance(value.get("host"), dict) or not isinstance(value.get("execute_probes"), bool):
        return False
    execute_probes = value["execute_probes"]
    checks = value.get("checks")
    workflows = value.get("workflows")
    summary = value.get("summary")
    if not isinstance(checks, dict) or not isinstance(workflows, dict) or not isinstance(summary, dict):
        return False

    for name, check in checks.items():
        if not isinstance(name, str) or not name or not isinstance(check, dict):
            return False
        status = check.get("status")
        discovered = check.get("discovered")
        probe = check.get("probe")
        if status not in _ENVIRONMENT_CHECK_STATUSES or not isinstance(discovered, bool):
            return False
        if status in {"discovered", "verified", "failed"} and not discovered:
            return False
        if status == "unavailable" and discovered:
            return False
        if probe is not None and not isinstance(probe, dict):
            return False
        probe_status = probe.get("status") if isinstance(probe, dict) else None
        if status == "verified" and (not execute_probes or probe_status != "ok"):
            return False
        if status == "failed" and (not execute_probes or probe_status != "failed"):
            return False
        if status in {"discovered", "unavailable"} and probe is not None:
            return False

    actual_workflow_counts = {
        status: 0 for status in _ENVIRONMENT_WORKFLOW_STATUSES
    }
    for name, workflow in workflows.items():
        if not isinstance(name, str) or not name or not isinstance(workflow, dict):
            return False
        status = workflow.get("status")
        if status not in _ENVIRONMENT_WORKFLOW_STATUSES:
            return False
        if not isinstance(workflow.get("ready"), bool) or not isinstance(
            workflow.get("verified"), bool
        ):
            return False
        required = workflow.get("required")
        any_of = workflow.get("any_of")
        if (
            not isinstance(required, list)
            or not isinstance(any_of, list)
            or (not required and not any_of)
            or any(
                not isinstance(item, str) or item not in checks
                for item in [*required, *any_of]
            )
        ):
            return False

        if status == "unsupported_host":
            if workflow["ready"] or workflow["verified"]:
                return False
        else:
            required_checks = [checks[item] for item in required]
            alternative_checks = [checks[item] for item in any_of]
            dependency_checks = [*required_checks, *alternative_checks]
            ready = all(item["discovered"] for item in required_checks) and (
                not alternative_checks
                or any(item["discovered"] for item in alternative_checks)
            )
            partially_ready = any(item["discovered"] for item in dependency_checks)
            verified = ready and all(
                item["status"] == "verified" for item in required_checks
            ) and (
                not alternative_checks
                or any(item["status"] == "verified" for item in alternative_checks)
            )
            failed = any(item["status"] == "failed" for item in dependency_checks)
            if verified:
                expected_status = "verified"
            elif failed:
                expected_status = "failed"
            elif ready:
                expected_status = "dependency_gated"
            elif partially_ready:
                expected_status = "partial"
            else:
                expected_status = "unavailable"
            if (
                workflow["ready"] is not ready
                or workflow["verified"] is not verified
                or status != expected_status
            ):
                return False
        actual_workflow_counts[status] += 1

    summary_keys = ("total", *_ENVIRONMENT_WORKFLOW_STATUSES)
    counts: dict[str, int] = {}
    for key in summary_keys:
        count = summary.get(key)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            return False
        counts[key] = count
    workflows_valid = (
        counts["total"] == len(workflows)
        and counts["total"]
        == sum(counts[status] for status in _ENVIRONMENT_WORKFLOW_STATUSES)
        and all(
            counts[status] == actual_workflow_counts[status]
            for status in _ENVIRONMENT_WORKFLOW_STATUSES
        )
    )
    if not workflows_valid:
        return False
    if schema_version == 1:
        return True
    return _valid_environment_acceptance_fixtures(
        value.get("acceptance_fixtures"), summary
    )


def _valid_environment_acceptance_fixtures(
    fixtures: Any, summary: Mapping[str, Any]
) -> bool:
    if not isinstance(fixtures, list):
        return False
    status_counts = {status: 0 for status in _ENVIRONMENT_FIXTURE_STATUSES}
    fixture_ids: set[str] = set()
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            return False
        fixture_id = fixture.get("id")
        if (
            not isinstance(fixture_id, str)
            or not fixture_id.strip()
            or fixture_id in fixture_ids
        ):
            return False
        fixture_ids.add(fixture_id)
        if fixture.get("phase") not in {"P0", "P1", "P2", "P3", "P4"}:
            return False
        for key in (
            "capability",
            "evidence_level",
            "host",
            "command",
            "acceptance_boundary",
        ):
            if not isinstance(fixture.get(key), str) or not fixture[key].strip():
                return False
        status = fixture.get("status")
        if status not in _ENVIRONMENT_FIXTURE_STATUSES:
            return False
        if not isinstance(fixture.get("host_supported"), bool) or not isinstance(
            fixture.get("live_verified"), bool
        ):
            return False
        if (status == "unsupported_host") is fixture["host_supported"]:
            return False
        if fixture["live_verified"] is not (status == "live_verified"):
            return False
        expected_artifacts = fixture.get("expected_artifacts")
        if (
            not isinstance(expected_artifacts, list)
            or not expected_artifacts
            or any(not isinstance(item, str) or not item for item in expected_artifacts)
        ):
            return False
        workflow_states = fixture.get("workflow_states")
        if not isinstance(workflow_states, dict) or any(
            not isinstance(name, str)
            or not name
            or state not in {*_ENVIRONMENT_WORKFLOW_STATUSES, "missing"}
            for name, state in workflow_states.items()
        ):
            return False
        gate_env = fixture.get("gate_env", [])
        configured_gates = fixture.get("configured_gates")
        missing_gates = fixture.get("missing_gates")
        if any(
            not isinstance(items, list)
            or any(not isinstance(item, str) or not item for item in items)
            for items in (gate_env, configured_gates, missing_gates)
        ):
            return False
        if set(configured_gates) & set(missing_gates):
            return False
        if set(configured_gates) | set(missing_gates) != set(gate_env):
            return False
        status_counts[status] += 1

    readiness_statuses = _ENVIRONMENT_FIXTURE_STATUSES - {"live_verified"}
    readiness_counts: dict[str, int] = {}
    for status in readiness_statuses:
        key = f"acceptance_fixture_{status}"
        count = summary.get(key)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            return False
        readiness_counts[status] = count

    total = summary.get("acceptance_fixture_total")
    live_count = summary.get("acceptance_fixture_live_verified", 0)
    if (
        isinstance(total, bool)
        or not isinstance(total, int)
        or total != len(fixtures)
        or isinstance(live_count, bool)
        or not isinstance(live_count, int)
        or live_count != status_counts["live_verified"]
        or sum(readiness_counts.values()) != total
    ):
        return False

    # A merged report replaces a verified fixture's readiness status with
    # ``live_verified`` while retaining the original readiness summary.
    return all(
        status_counts[status] <= readiness_counts[status]
        for status in readiness_statuses
    ) and sum(
        readiness_counts[status] - status_counts[status]
        for status in readiness_statuses
    ) == live_count


def _session_directories(workspace: Path) -> tuple[Path, ...]:
    """Return top-level and local-runner session directories for a workspace."""

    experiment_root = workspace / "experiments"
    local_session_dirs = (
        tuple(sorted(path for path in experiment_root.glob("*/analysis/sessions") if path.is_dir()))
        if experiment_root.is_dir()
        else ()
    )
    return (workspace / "sessions", *local_session_dirs)


def _load_records(
    directories: Iterable[Path], diagnostics: dict[str, Any]
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    for directory in directories:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            source_path = path.resolve()
            if source_path in seen_paths:
                continue
            seen_paths.add(source_path)
            value = _load_json(path, diagnostics)
            if isinstance(value, dict):
                record = dict(value)
                record.setdefault("source_file", path.name)
                records.append(record)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        record = dict(item)
                        record.setdefault("source_file", path.name)
                        records.append(record)
                    else:
                        diagnostics["invalid_records"] += 1
            elif value is not None:
                diagnostics["invalid_records"] += 1
    return records


def _load_json(path: Path, diagnostics: dict[str, Any]) -> Any:
    if not path.is_file():
        return None
    diagnostics["files_scanned"] += 1
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        diagnostics["malformed_json"] += 1
        diagnostics["skipped_files"].append({"path": str(path), "error": str(error)})
        return None
    diagnostics["files_loaded"] += 1
    return value


def _record_timestamp(record: dict[str, Any]) -> str:
    for key in ("updated_at", "timestamp", "created_at", "started_at"):
        value = record.get(key)
        if value is not None:
            return str(value)
    return ""


def _load_binary_patches(workspace: Path, diagnostics: dict[str, Any]) -> dict[str, Any]:
    """Collect structurally valid, output-associated patch audit manifests.

    Patch commands may write artifacts beside a requested output, so manifests
    are discovered recursively rather than assuming one fixed session layout.
    A file merely named ``patch_manifest.json`` is not sufficient evidence of a
    completed patch: it must match the patch tool's schema and either live in
    the default patch-artifact directory or have a matching rollback plan.
    A patch manifest and its rollback instructions in the same directory describe
    one patch audit item. A rollback result manifest is a separate audit item.
    """

    artifacts: dict[tuple[Path, str], dict[str, Any]] = {}
    try:
        paths = sorted(
            {
                *workspace.rglob("patch_manifest.json"),
                *workspace.rglob("rollback.json"),
                *workspace.rglob("rollback_manifest.json"),
            },
            key=lambda path: str(path),
        )
    except OSError:
        paths = []

    loaded: dict[Path, dict[str, Any]] = {}
    for path in paths:
        value = _load_json(path, diagnostics)
        if not isinstance(value, dict):
            if value is not None:
                diagnostics["invalid_records"] += 1
            continue
        loaded[path] = value

    for path, value in loaded.items():
        # ``rollback.json`` contains restoration instructions for a patch
        # audit, not a separately applied patch result.  It is consulted below
        # only to prove a custom artifact directory belongs to the patch tool.
        if path.name == "rollback.json":
            continue
        audit_type = "rollback" if path.name == "rollback_manifest.json" else "patch"
        if not _is_trusted_patch_audit(path, value, loaded):
            diagnostics["invalid_records"] += 1
            diagnostics["skipped_files"].append(
                {
                    "path": str(path),
                    "error": "ignored untrusted or incomplete binary patch audit manifest",
                }
            )
            continue
        item = artifacts.setdefault(
            (path.parent.resolve(), audit_type),
            {"timestamp": "", "audit_type": audit_type},
        )
        item["artifact_path"] = str(path.parent)
        if path.name == "rollback_manifest.json":
            item["rollback_manifest_path"] = str(path)
            fields = {
                "patched_path": "source_path",
                "restored_path": "patched_path",
                "patched_sha256": "source_sha256",
                "restored_sha256": "patched_sha256",
                "status": "status",
                "dry_run": "dry_run",
            }
        else:
            item["manifest_path" if path.name == "patch_manifest.json" else "rollback_path"] = str(path)
            fields = {
                "source_path": "source_path",
                "patched_path": "patched_path",
                "source_sha256": "source_sha256",
                "patched_sha256": "patched_sha256",
                "status": "status",
                "dry_run": "dry_run",
            }
        for key, normalized_key in fields.items():
            if key in value and value[key] is not None:
                item[normalized_key] = value[key]
        if isinstance(value.get("operations"), list) and (
            path.name != "rollback.json" or "operation_count" not in item
        ):
            item["operation_count"] = len(value["operations"])
        timestamp = _record_timestamp(value)
        if timestamp:
            item["timestamp"] = timestamp
        elif not item["timestamp"]:
            try:
                item["timestamp"] = datetime.fromtimestamp(
                    path.stat().st_mtime, tz=timezone.utc
                ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            except OSError:
                pass

    recent: list[dict[str, Any]] = []
    for item in artifacts.values():
        status = str(item.get("status") or ("planned" if item.get("dry_run") else "unknown"))
        recent.append(
            {
                "source_path": _audit_text(item.get("source_path")),
                "patched_path": _audit_text(item.get("patched_path")),
                "source_sha256": _audit_text(item.get("source_sha256")),
                "patched_sha256": _audit_text(item.get("patched_sha256")),
                "operation_count": _audit_count(item.get("operation_count")),
                "timestamp": _audit_text(item.get("timestamp")),
                "status": status,
                "dry_run": bool(item.get("dry_run")),
                "artifact_path": _audit_text(item.get("artifact_path")),
                "audit_type": _audit_text(item.get("audit_type")) or "patch",
            }
        )
    recent.sort(key=lambda item: item["timestamp"], reverse=True)
    return {
        "count": len(recent),
        "dry_run_count": sum(item["dry_run"] for item in recent),
        "applied_count": sum(not item["dry_run"] and item["status"].lower() == "ok" for item in recent),
        "recent": recent[:20],
    }


def _load_evidence_manifests(workspace: Path, diagnostics: dict[str, Any]) -> dict[str, Any]:
    """Verify discovered evidence packages before exposing their status in UI.

    Dashboard data must not treat a file merely named ``evidence-manifest.json``
    as trusted. Each candidate is parsed and verified through the same path and
    hash checks exposed by the CLI. Invalid packages remain visible as failed
    audit rows rather than being mistaken for successful analysis evidence.
    """

    try:
        paths = sorted(workspace.rglob("evidence-manifest.json"), key=lambda path: str(path))
    except OSError:
        paths = []

    rows: list[dict[str, Any]] = []
    for path in paths:
        payload = _load_json(path, diagnostics)
        if not isinstance(payload, dict):
            if payload is not None:
                diagnostics["invalid_records"] += 1
            continue
        try:
            from .evidence import EVIDENCE_MANIFEST_SCHEMA, verify_manifest

            verification = verify_manifest(path)
        except Exception as error:  # noqa: BLE001 - dashboard remains usable without optional data
            verification = {
                "status": "failed",
                "valid": False,
                "verified_file_count": 0,
                "unavailable_stage_count": 0,
                "issues": [{"kind": "verification_error", "detail": f"{type(error).__name__}: {error}"}],
            }
            EVIDENCE_MANIFEST_SCHEMA = "reverse_analyzer.evidence_manifest/v1"

        artifacts = payload.get("artifacts")
        artifact_count = len(artifacts) if isinstance(artifacts, list) else 0
        covered_file_count = sum(
            1
            for item in artifacts or []
            if isinstance(item, dict)
            and item.get("sha256")
            and str(item.get("status") or "ok").lower()
            in {"ok", "succeeded", "success", "available", "complete", "completed"}
        )
        issues = verification.get("issues") if isinstance(verification.get("issues"), list) else []
        try:
            relative_path = path.resolve().relative_to(workspace.resolve()).as_posix()
        except ValueError:
            relative_path = str(path)
        rows.append(
            {
                "manifest_path": relative_path,
                "manifest_id": payload.get("manifest_id"),
                "schema": payload.get("schema"),
                "schema_valid": payload.get("schema") == EVIDENCE_MANIFEST_SCHEMA,
                "status": "ok" if verification.get("valid") else "failed",
                "artifact_count": artifact_count,
                "covered_file_count": covered_file_count,
                "verified_file_count": _audit_count(verification.get("verified_file_count")),
                "unavailable_stage_count": _audit_count(verification.get("unavailable_stage_count")),
                "issue_count": len(issues),
                "issue_kinds": sorted(
                    {str(item.get("kind") or "unknown") for item in issues if isinstance(item, dict)}
                ),
            }
        )

    rows.sort(key=lambda item: (item["status"] != "failed", item["manifest_path"]))
    return {
        "count": len(rows),
        "valid_count": sum(1 for item in rows if item["status"] == "ok"),
        "failed_count": sum(1 for item in rows if item["status"] != "ok"),
        "covered_file_count": sum(int(item["covered_file_count"]) for item in rows),
        "verified_file_count": sum(int(item["verified_file_count"]) for item in rows),
        "recent": rows[:50],
    }


def _is_trusted_patch_audit(
    path: Path,
    payload: dict[str, Any],
    loaded: dict[Path, dict[str, Any]],
) -> bool:
    """Accept only schema-valid patch outputs, never filename-only matches."""

    if path.name == "patch_manifest.json":
        if not _is_patch_apply_manifest(payload):
            return False
        # The normal CLI location is explicit.  A caller may also select a
        # custom artifact directory, in which case the paired rollback plan
        # supplies the association proof.
        if path.parent.name.endswith(".patch-artifacts"):
            return True
        return _is_matching_rollback_plan(payload, loaded.get(path.parent / "rollback.json"))
    if path.name == "rollback_manifest.json":
        return _is_patch_rollback_manifest(payload)
    return False


def _is_patch_apply_manifest(payload: dict[str, Any]) -> bool:
    return (
        _has_schema_v1(payload)
        and _has_text_fields(payload, "source_path", "patched_path")
        and _has_sha256_fields(payload, "source_sha256", "patched_sha256")
        and _has_audit_state(payload)
        and isinstance(payload.get("operations"), list)
    )


def _is_patch_rollback_manifest(payload: dict[str, Any]) -> bool:
    return (
        _has_schema_v1(payload)
        and _has_text_fields(payload, "patched_path", "restored_path")
        and _has_sha256_fields(payload, "patched_sha256", "restored_sha256")
        and _has_audit_state(payload)
        and isinstance(payload.get("operations"), list)
    )


def _is_matching_rollback_plan(
    manifest: dict[str, Any],
    rollback: dict[str, Any] | None,
) -> bool:
    if not isinstance(rollback, dict):
        return False
    if not _has_schema_v1(rollback) or not _has_text_fields(rollback, "source_path"):
        return False
    if not _has_sha256_fields(rollback, "source_sha256", "patched_sha256"):
        return False
    if not isinstance(rollback.get("operations"), list):
        return False
    return (
        rollback.get("source_path") == manifest.get("source_path")
        and rollback.get("source_sha256") == manifest.get("source_sha256")
        and rollback.get("patched_sha256") == manifest.get("patched_sha256")
    )


def _has_schema_v1(payload: dict[str, Any]) -> bool:
    return payload.get("schema_version") == 1 and not isinstance(payload.get("schema_version"), bool)


def _has_text_fields(payload: dict[str, Any], *names: str) -> bool:
    return all(isinstance(payload.get(name), str) and bool(payload[name].strip()) for name in names)


def _has_sha256_fields(payload: dict[str, Any], *names: str) -> bool:
    return all(
        isinstance(payload.get(name), str)
        and len(payload[name]) == 64
        and all(character in "0123456789abcdefABCDEF" for character in payload[name])
        for name in names
    )


def _has_audit_state(payload: dict[str, Any]) -> bool:
    return (
        isinstance(payload.get("dry_run"), bool)
        and isinstance(payload.get("status"), str)
        and payload["status"].lower() in {"ok", "planned"}
    )


def _audit_text(value: Any) -> str | None:
    """Return bounded scalar audit data; manifests must not expand dashboard data."""

    if value is None:
        return None
    return str(value)[:2048]


def _audit_count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _number(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    try:
        number = float(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def _recommend_dynamic_profile(data: Any) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    profiles = data.get("profiles", {}) if isinstance(data, dict) else {}
    if not isinstance(profiles, dict):
        profiles = {}
    for name, value in profiles.items():
        if not isinstance(value, dict):
            continue
        record = dict(value)
        runs = max(1, int(_number(record.get("runs"))))
        score = (
            _number(record.get("success_rate")) * 10
            + _number(record.get("avg_events")) * 0.1
            - _number(record.get("avg_planned_hooks")) * 0.02
            + min(2.0, runs * 0.1)
        )
        record.update(profile=str(record.get("profile") or name), score=round(score, 3))
        candidates.append(record)
    if not candidates:
        return {"profile": "quick", "score": 0.0, "reason": "no dynamic profile history"}
    candidates.sort(key=lambda item: (-_number(item.get("score")), -_number(item.get("runs")), str(item["profile"])))
    best = candidates[0]
    return {key: best[key] for key in ("profile", "score", "runs", "success_rate", "avg_events", "avg_planned_hooks") if key in best}


def _recommend_gui_strategy(data: Any) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    strategies = data.get("strategies", {}) if isinstance(data, dict) else {}
    if not isinstance(strategies, dict):
        strategies = {}
    for key, value in strategies.items():
        if not isinstance(value, dict):
            continue
        record = dict(value)
        runs = max(1, int(_number(record.get("runs"))))
        framework = str(record.get("framework") or str(key).split(":", 1)[0] or "unknown")
        strategy = str(record.get("strategy") or str(key).split(":", 1)[-1])
        score = (
            _number(record.get("success_rate")) * 10
            + _number(record.get("avg_visual_similarity")) * 5
            + _number(record.get("avg_control_match_rate")) * 2
            + _number(record.get("avg_text_match_rate")) * 2
            + min(2.0, runs * 0.1)
        )
        record.update(framework=framework, strategy=strategy, score=round(score, 3))
        candidates.append(record)
    if not candidates:
        return {
            "framework": None,
            "strategy": "manual_assisted_visual_reconstruction",
            "score": 0.0,
            "reason": "no GUI strategy history",
        }
    candidates.sort(key=lambda item: (-_number(item.get("score")), -_number(item.get("runs")), item["framework"], item["strategy"]))
    best = candidates[0]
    keys = ("framework", "strategy", "score", "runs", "success_rate", "avg_visual_similarity", "avg_control_match_rate", "avg_text_match_rate")
    return {key: best[key] for key in keys if key in best}


def _knowledge_session_records(
    value: Any,
    diagnostics: dict[str, Any],
) -> list[dict[str, Any]]:
    """Normalize KnowledgeBase session history without treating metadata as sessions."""

    if value is None:
        return []
    if isinstance(value, dict):
        nested = value.get("sessions")
        if not isinstance(nested, list):
            nested = value.get("records")
        if isinstance(nested, list):
            value = nested
        elif any(key in value for key in ("session_id", "target", "timestamp")):
            value = [value]
        else:
            diagnostics["invalid_records"] += 1
            return []
    if not isinstance(value, list):
        diagnostics["invalid_records"] += 1
        return []

    records: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            diagnostics["invalid_records"] += 1
            continue
        record = dict(item)
        record.setdefault("source_file", "sessions.json")
        records.append(record)
    return records


def _build_knowledge_recommendations(
    stores: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Summarize all persisted recommendation stores using stable ordering."""

    labels = {
        "dynamic": "Dynamic profile",
        "gui": "GUI strategy",
        "patch": "Patch strategy",
        "engine": "Engine strategy",
        "protocol": "Protocol format",
        "source": "Source restoration",
        "llm_jailbreak": "Model jailbreak strategy",
    }
    results: dict[str, dict[str, Any]] = {}
    for namespace in labels:
        store = stores.get(namespace)
        container_name = "profiles" if namespace == "dynamic" else "strategies"
        container = store.get(container_name) if isinstance(store, dict) else {}
        if not isinstance(container, dict):
            container = {}
        if namespace == "dynamic":
            recommendation = _recommend_dynamic_profile(store)
        elif namespace == "gui":
            recommendation = _recommend_gui_strategy(store)
        else:
            recommendation = _recommend_strategy_store(store, namespace=namespace)
        results[namespace] = {
            "namespace": namespace,
            "label": labels[namespace],
            "candidate_count": sum(isinstance(item, dict) for item in container.values()),
            "total_runs": sum(
                max(0, int(_number(item.get("runs"))))
                for item in container.values()
                if isinstance(item, dict)
            ),
            "recommendation": recommendation,
        }
    return results


def _recommend_strategy_store(data: Any, *, namespace: str) -> dict[str, Any]:
    strategies = data.get("strategies") if isinstance(data, dict) else {}
    if not isinstance(strategies, dict):
        strategies = {}
    candidates: list[dict[str, Any]] = []
    for raw_key, raw_record in strategies.items():
        if not isinstance(raw_record, dict):
            continue
        key = str(raw_key)
        record = dict(raw_record)
        runs = max(0, int(_number(record.get("runs"))))
        if namespace == "patch":
            score = _patch_strategy_score(record, runs=runs)
        else:
            score = _generic_strategy_score(record, runs=runs)
        candidate = {
            "key": key,
            "score": round(score, 4),
            "runs": runs,
            "success_rate": _number(record.get("success_rate")),
        }
        if namespace == "patch":
            candidate["strategy"] = str(record.get("strategy") or key.split(":", 1)[-1])
            candidate["target_format"] = str(
                record.get("target_format") or key.split(":", 1)[0] or "unknown"
            )
        elif namespace == "llm_jailbreak":
            model, _, strategy = key.partition(":")
            known_models = record.get("models") if isinstance(record.get("models"), dict) else {}
            fallback_model = next(iter(known_models), model or "unknown")
            candidate["model"] = str(
                record.get("model") or record.get("last_model") or fallback_model
            )
            candidate["strategy"] = str(record.get("strategy") or strategy or key)
        for metric_name, metric_value in record.items():
            if metric_name.startswith("avg_") and isinstance(metric_value, (int, float)):
                candidate[metric_name] = metric_value
        candidates.append(candidate)

    if not candidates:
        defaults = {
            "patch": {"strategy": "inline_patch"},
            "engine": {"key": "unknown:static_engine_fingerprint"},
            "protocol": {"key": "protocol:protocol_strings_dynamic_fusion"},
            "source": {"key": "source:source_summary"},
            "llm_jailbreak": {"strategy": "roleplay"},
        }
        return {
            **defaults.get(namespace, {"key": None}),
            "score": 0.0,
            "reason": f"no {namespace} strategy history",
        }
    candidates.sort(
        key=lambda item: (
            -_number(item.get("score")),
            -_number(item.get("runs")),
            str(item.get("key") or ""),
        )
    )
    return candidates[0]


def _generic_strategy_score(record: dict[str, Any], *, runs: int) -> float:
    score = _number(record.get("success_rate")) * 100.0
    score += min(float(runs), 10.0) * 1.5
    for key, value in record.items():
        if not key.startswith("avg_") or isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        metric_name = key[4:].lower()
        sign = -1.0 if any(
            token in metric_name
            for token in ("risk", "overhead", "cost", "latency", "warning", "error", "failure", "hook")
        ) else 1.0
        if any(token in metric_name for token in ("similarity", "match_rate", "confidence", "coverage", "score")):
            score += sign * float(value) * 20.0
        elif any(token in metric_name for token in ("events", "controls", "widgets", "text", "nodes", "flows", "files", "functions")):
            score += sign * min(float(value), 100.0) / 5.0
        else:
            score += sign * min(float(value), 50.0) / 10.0
    return score


def _patch_strategy_score(record: dict[str, Any], *, runs: int) -> float:
    risk_counts = record.get("risk_counts") if isinstance(record.get("risk_counts"), dict) else {}
    risk_weights = {"critical": 4.0, "high": 2.0, "medium": 0.5, "warning": 0.25, "low": 0.1}
    risk_penalty = sum(
        risk_weights.get(str(name).lower(), 0.25) * max(0.0, _number(count))
        for name, count in risk_counts.items()
    ) / max(1, runs)
    return (
        _number(record.get("success_rate")) * 100.0
        + _number(record.get("verify_rate")) * 20.0
        + _number(record.get("apply_rate")) * 30.0
        + _number(record.get("rollback_rate")) * 15.0
        + min(float(runs), 10.0) * 1.5
        - min(60.0, risk_penalty * 10.0)
        - min(10.0, _number(record.get("avg_operation_count")) * 0.1)
    )


def _build_session_analytics(
    sessions: Iterable[dict[str, Any]],
    knowledge_sessions: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Build de-duplicated history, adjacent-session comparison, and trend data."""

    merged: dict[str, dict[str, Any]] = {}
    for source_name, records in (("session", sessions), ("knowledge", knowledge_sessions)):
        for index, raw_record in enumerate(records):
            if not isinstance(raw_record, dict):
                continue
            record = dict(raw_record)
            identity = _session_identity(record, fallback=f"{source_name}:{index}")
            current = merged.setdefault(identity, {"_sources": []})
            current["_sources"].append(source_name)
            for key, value in record.items():
                if value not in (None, "", [], {}):
                    current[key] = value
            current["session_key"] = identity

    records = list(merged.values())
    records.sort(
        key=lambda item: (_record_timestamp(item), str(item.get("session_key") or "")),
        reverse=True,
    )
    for record in records:
        record["_sources"] = sorted(set(record.get("_sources") or []))

    points = [_session_trend_point(record) for record in reversed(records[:100])]
    status_counts: dict[str, int] = {}
    for record in records:
        status = str(record.get("status") or "unknown").lower()
        status_counts[status] = status_counts.get(status, 0) + 1

    compare = _compare_sessions(records[0], records[1]) if len(records) >= 2 else {
        "available": False,
        "reason": "at least two distinct sessions are required",
        "latest": _session_compare_side(records[0]) if records else None,
        "previous": None,
        "deltas": {},
        "recommendation_changes": [],
    }
    completed = sum(
        count
        for status, count in status_counts.items()
        if status in {"ok", "completed", "success", "succeeded", "passed"}
    )
    return {
        "record_count": len(records),
        "records": records[:50],
        "compare": compare,
        "trend": {
            "point_count": len(points),
            "status_counts": status_counts,
            "completion_rate": round(completed / len(records), 4) if records else 0.0,
            "points": points,
        },
    }


def _session_identity(record: dict[str, Any], *, fallback: str) -> str:
    session_id = record.get("session_id") or record.get("id")
    if session_id not in (None, ""):
        return f"id:{session_id}"
    target = record.get("target") or record.get("sample_id") or record.get("path")
    timestamp = _record_timestamp(record)
    if target or timestamp:
        return f"record:{target or ''}:{timestamp}"
    return fallback


_SESSION_METRIC_PATHS = {
    "findings": ("finding_count",),
    "artifacts": ("artifact_count",),
    "evidence_files": ("evidence_integrity", "covered_file_count"),
    "semantic_modules": ("semantic_ir", "module_count"),
    "semantic_entities": ("semantic_ir", "entity_count"),
    "behavior_nodes": ("behavior_graph", "node_count"),
    "behavior_edges": ("behavior_graph", "edge_count"),
    "verification_score": ("reconstruction_verification", "score"),
}


def _session_metrics(record: dict[str, Any]) -> dict[str, float]:
    metrics: dict[str, float] = {}
    for name, path in _SESSION_METRIC_PATHS.items():
        value: Any = record
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if value is None or isinstance(value, bool):
            continue
        try:
            metrics[name] = round(float(value), 4)
        except (TypeError, ValueError):
            continue
    return metrics


def _session_recommendations(record: dict[str, Any]) -> dict[str, str]:
    fields = {
        "dynamic": ("recommended_dynamic_profile", "profile"),
        "gui": ("recommended_gui_strategy", "strategy"),
        "patch": ("recommended_patch_strategy", "strategy"),
        "engine": ("recommended_engine_strategy", "key"),
        "protocol": ("recommended_protocol_strategy", "key"),
        "source": ("recommended_source_strategy", "key"),
    }
    recommendations: dict[str, str] = {}
    for namespace, (field, preferred_key) in fields.items():
        value = record.get(field)
        if isinstance(value, dict):
            selected = value.get(preferred_key) or value.get("key") or value.get("strategy")
        else:
            selected = value
        if selected not in (None, ""):
            recommendations[namespace] = str(selected)
    return recommendations


def _session_compare_side(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "session_id": record.get("session_id") or record.get("id") or record.get("session_key"),
        "target": record.get("target") or record.get("sample_id") or record.get("path"),
        "status": record.get("status") or "unknown",
        "timestamp": _record_timestamp(record),
        "metrics": _session_metrics(record),
        "recommendations": _session_recommendations(record),
    }


def _compare_sessions(latest: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    latest_side = _session_compare_side(latest)
    previous_side = _session_compare_side(previous)
    latest_metrics = latest_side["metrics"]
    previous_metrics = previous_side["metrics"]
    deltas = {
        key: round(latest_metrics.get(key, 0.0) - previous_metrics.get(key, 0.0), 4)
        for key in sorted(set(latest_metrics) | set(previous_metrics))
    }
    recommendation_changes = []
    latest_recommendations = latest_side["recommendations"]
    previous_recommendations = previous_side["recommendations"]
    for namespace in sorted(set(latest_recommendations) | set(previous_recommendations)):
        before = previous_recommendations.get(namespace)
        after = latest_recommendations.get(namespace)
        if before != after:
            recommendation_changes.append(
                {"namespace": namespace, "previous": before, "latest": after}
            )
    return {
        "available": True,
        "latest": latest_side,
        "previous": previous_side,
        "deltas": deltas,
        "recommendation_changes": recommendation_changes,
    }


def _session_trend_point(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "session_id": record.get("session_id") or record.get("id") or record.get("session_key"),
        "timestamp": _record_timestamp(record),
        "status": record.get("status") or "unknown",
        "metrics": _session_metrics(record),
        "recommendations": _session_recommendations(record),
    }


def _workspace_artifact_references(
    *,
    reports: Iterable[dict[str, Any]],
    sessions: Iterable[dict[str, Any]],
    binary_patches: dict[str, Any],
    evidence_manifests: dict[str, Any],
    source_reconstruction: dict[str, Any],
    environment_validation: dict[str, Any],
    acceptance_history: dict[str, Any],
) -> list[dict[str, Any]]:
    """Collect workspace artifact candidates that are not embedded in report artifacts."""

    references: list[dict[str, Any]] = []

    def add(path: Any, *, label: str, domain: str, kind: str, source: Any = None) -> None:
        if isinstance(path, str) and path.strip():
            references.append(
                {
                    "path": path,
                    "label": label,
                    "domain": domain,
                    "kind": kind,
                    "source": str(source) if source not in (None, "") else None,
                }
            )

    for entry in reports:
        source = entry.get("source_path")
        add(source, label="Analysis report", domain="report", kind="report", source=source)
    for session in sessions:
        source = session.get("source_file") or session.get("session_id")
        for key in ("out_dir", "report_path", "manifest_path", "artifact_path", "project_dir"):
            add(
                session.get(key),
                label=key.replace("_", " ").title(),
                domain="session",
                kind=key,
                source=source,
            )
        evidence = session.get("evidence_integrity")
        if isinstance(evidence, dict):
            add(
                evidence.get("manifest_path"),
                label="Session evidence manifest",
                domain="session",
                kind="evidence_manifest",
                source=source,
            )
    for patch in binary_patches.get("recent", []):
        if isinstance(patch, dict):
            add(
                patch.get("artifact_path"),
                label=f"{str(patch.get('audit_type') or 'patch').title()} artifacts",
                domain="patch",
                kind="patch_audit",
                source=patch.get("source_path"),
            )
    for manifest in evidence_manifests.get("recent", []):
        if isinstance(manifest, dict):
            add(
                manifest.get("manifest_path"),
                label="Evidence manifest",
                domain="evidence",
                kind="evidence_manifest",
            )
    add(
        environment_validation.get("source_path"),
        label="Environment validation report",
        domain="environment",
        kind="environment_validation",
    )
    for record in acceptance_history.get("records", []):
        if not isinstance(record, dict):
            continue
        source = record.get("source_path")
        add(
            source,
            label=f"Acceptance record: {record.get('fixture_id') or 'fixture'}",
            domain="acceptance",
            kind="acceptance_record",
            source=source,
        )
        add(
            record.get("record_path"),
            label=f"Acceptance record path: {record.get('fixture_id') or 'fixture'}",
            domain="acceptance",
            kind="acceptance_record",
            source=source,
        )
        for artifact in record.get("observed_artifacts", []):
            if isinstance(artifact, dict):
                add(
                    artifact.get("path"),
                    label=str(artifact.get("label") or "Observed acceptance artifact"),
                    domain="acceptance",
                    kind=str(artifact.get("kind") or "acceptance_artifact"),
                    source=source,
                )
    for project in source_reconstruction.get("projects", []):
        if not isinstance(project, dict):
            continue
        project_path = project.get("relative_path") or project.get("project_dir") or project.get("path")
        add(
            project_path,
            label=str(project.get("name") or "Reconstructed source project"),
            domain="source",
            kind="source_project",
        )
        project_artifacts = project.get("artifacts")
        if (
            isinstance(project_path, str)
            and isinstance(project_artifacts, list)
            and "analysis/equivalence_assessment.json" in project_artifacts
        ):
            project_root = project_path.rstrip("/\\")
            add(
                f"{project_root}/analysis/equivalence_assessment.json",
                label="Observed-evidence equivalence assessment",
                domain="source",
                kind="source_equivalence_assessment",
                source=project_path,
            )
    return references


def _attach_acceptance_artifact_links(
    acceptance_history: dict[str, Any], artifact_navigation: dict[str, Any]
) -> None:
    items = artifact_navigation.get("items", [])
    for record in acceptance_history.get("records", []):
        if not isinstance(record, dict):
            continue
        source = str(record.get("source_path") or "")
        links: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict) or "acceptance" not in item.get("domains", []):
                continue
            if source not in item.get("sources", []) and item.get("path") != source:
                continue
            path = str(item.get("path") or "")
            if not path or path in seen:
                continue
            seen.add(path)
            links.append(
                {
                    "path": path,
                    "label": item.get("label") or path,
                    "kind": item.get("kind"),
                    "exists": item.get("exists") is True,
                    "href": item.get("href"),
                }
            )
        record["artifact_links"] = links


def _build_artifact_navigation(
    references: Iterable[dict[str, Any]],
    *,
    workspace: Path,
    destination: Path,
) -> dict[str, Any]:
    """Resolve artifact links while preventing references from escaping the workspace."""

    root = workspace.resolve()
    dashboard_root = destination.resolve()
    resolved_items: dict[str, dict[str, Any]] = {}
    blocked_count = 0
    for reference in references:
        raw_path = reference.get("path") if isinstance(reference, dict) else None
        if not isinstance(raw_path, str) or not raw_path.strip():
            continue
        resolved = _resolve_workspace_artifact(
            raw_path,
            source=reference.get("source"),
            workspace=root,
        )
        if resolved is None:
            blocked_count += 1
            continue
        path, exists = resolved
        relative = path.relative_to(root).as_posix()
        item = resolved_items.get(relative)
        domain = str(reference.get("domain") or "other")
        kind = str(reference.get("kind") or "artifact")
        if item is None:
            item = {
                "path": relative,
                "label": str(reference.get("label") or path.name or relative),
                "domain": domain,
                "kind": kind,
                "domains": [],
                "kinds": [],
                "sources": [],
                "exists": exists,
                "is_directory": exists and path.is_dir(),
                "size_bytes": path.stat().st_size if exists and path.is_file() else None,
                "modified_at": _path_modified_at(path) if exists else None,
            }
            if exists:
                href = os.path.relpath(path, dashboard_root).replace(os.sep, "/")
                item["href"] = quote(href, safe="/.:@-_")
            resolved_items[relative] = item
        item["domains"].append(domain)
        item["kinds"].append(kind)
        source = reference.get("source")
        if source not in (None, ""):
            item["sources"].append(str(source))

    items = list(resolved_items.values())
    for item in items:
        item["domains"] = sorted(set(item["domains"]))
        item["kinds"] = sorted(set(item["kinds"]))
        item["sources"] = sorted(set(item["sources"]))[:20]
    items.sort(key=lambda item: (not item["exists"], item["domain"], item["path"]))
    groups = []
    for domain in sorted({item["domain"] for item in items}):
        domain_items = [item for item in items if item["domain"] == domain]
        groups.append(
            {
                "domain": domain,
                "count": len(domain_items),
                "available_count": sum(item["exists"] for item in domain_items),
                "items": domain_items,
            }
        )
    return {
        "count": len(items),
        "available_count": sum(item["exists"] for item in items),
        "missing_count": sum(not item["exists"] for item in items),
        "blocked_count": blocked_count,
        "items": items[:500],
        "groups": groups,
    }


def _resolve_workspace_artifact(
    raw_path: str,
    *,
    source: Any,
    workspace: Path,
) -> tuple[Path, bool] | None:
    value = raw_path.strip()
    if not value or "\x00" in value or re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
        return None
    path = Path(value).expanduser()
    candidates: list[Path] = []
    if path.is_absolute():
        candidates.append(path)
    else:
        candidates.append(workspace / path)
        if isinstance(source, str) and source.strip():
            source_path = Path(source.strip())
            if not source_path.is_absolute():
                source_path = workspace / source_path
            source_base = source_path if source_path.is_dir() else source_path.parent
            candidates.append(source_base / path)

    safe_candidates: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(workspace)
        except (OSError, RuntimeError, ValueError):
            continue
        if resolved not in safe_candidates:
            safe_candidates.append(resolved)
        if resolved.exists():
            return resolved, True
    if safe_candidates:
        return safe_candidates[0], False
    return None


def _path_modified_at(path: Path) -> str | None:
    try:
        return (
            datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except OSError:
        return None


def _write_json(path: Path, data: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def _embedded_json(data: dict[str, Any]) -> str:
    """Encode JSON safely for an HTML script element, including ``</script>``."""

    return json.dumps(data, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _html_document(data: dict[str, Any]) -> str:
    payload = _embedded_json(data)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reverse Lab Command Deck</title>
  <style>
    :root {{ color-scheme: dark; --ink:#edf4f2; --muted:#8ca19c; --line:#29403d; --panel:#101b1a; --base:#07100f; --accent:#56d8ae; --amber:#f8bf56; --red:#ef7373; }}
    * {{ box-sizing:border-box; }} body {{ margin:0; background:var(--base); color:var(--ink); font:14px/1.45 ui-monospace,Consolas,monospace; }}
    header {{ padding:28px max(24px, calc((100vw - 1280px)/2)); border-bottom:1px solid var(--line); background:#0a1513; }}
    h1 {{ margin:0; font-size:24px; letter-spacing:0; }} .eyebrow {{ color:var(--accent); font-size:11px; text-transform:uppercase; margin-bottom:7px; }}
    main {{ max-width:1280px; margin:auto; padding:24px; }} .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:24px; }}
    .kpi,.panel {{ border:1px solid var(--line); background:var(--panel); border-radius:4px; }} .kpi {{ padding:15px; }} .kpi b {{ display:block; color:var(--accent); font-size:26px; margin-top:4px; }}
    .grid {{ display:grid; grid-template-columns:1.25fr .75fr; gap:16px; }} .panel {{ padding:18px; margin-bottom:16px; }} h2 {{ font-size:14px; margin:0 0 14px; color:#c9d8d4; text-transform:uppercase; }}
    .toolbar {{ display:flex; gap:10px; margin-bottom:12px; }} input,select {{ color:var(--ink); background:#0a1413; border:1px solid var(--line); padding:9px; border-radius:3px; font:inherit; }} input {{ flex:1; min-width:0; }}
    table {{ width:100%; border-collapse:collapse; }} th,td {{ padding:10px 7px; border-top:1px solid #1d302e; text-align:left; vertical-align:top; }} th {{ color:var(--muted); font-size:11px; text-transform:uppercase; }}
    .badge {{ display:inline-block; padding:2px 7px; border:1px solid var(--line); border-radius:2px; color:var(--amber); }} .recommendation {{ border-left:3px solid var(--accent); padding-left:12px; margin:14px 0; }}
    .empty {{ color:var(--muted); padding:20px 0; text-align:center; }} .meta {{ color:var(--muted); font-size:12px; }} ul {{ margin:0; padding-left:18px; }}
    .source-panel {{ margin-top:16px; }} .source-summary {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px; color:var(--muted); }} .source-project {{ border-top:1px solid #1d302e; padding:14px 0; }} .source-project:first-child {{ border-top:0; padding-top:0; }} .source-head {{ display:flex; justify-content:space-between; gap:12px; align-items:baseline; }} .source-head strong {{ color:var(--accent); }} .source-metrics {{ display:flex; flex-wrap:wrap; gap:10px; margin:8px 0; color:var(--muted); font-size:12px; }} .table-scroll {{ overflow-x:auto; }} .section-label {{ margin:14px 0 5px; color:#c9d8d4; font-size:12px; }} .evidence-boundary {{ border-left:2px solid var(--amber); padding:7px 10px; margin:9px 0; color:var(--muted); font-size:12px; }} details {{ margin-top:9px; }} summary {{ cursor:pointer; color:#c9d8d4; }} .source-files,.analysis-grid,.artifact-grid,.campaign-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:8px; margin-top:10px; }} .source-file,.analysis-card,.artifact-group,.audit-record,.campaign-card {{ border:1px solid #1d302e; background:#0a1413; padding:11px; border-radius:3px; }} .analysis-card h3,.artifact-group h3,.campaign-card h3 {{ margin:0 0 8px; font-size:13px; color:var(--accent); }} .analysis-card.is-low {{ border-color:var(--amber); }} .attempt-tree {{ display:grid; gap:6px; margin-top:8px; }} .attempt-node {{ border-left:3px solid var(--line); padding:7px 9px; background:#0d1817; }} .attempt-node.success {{ border-left-color:var(--accent); }} .attempt-node.failed {{ border-left-color:var(--red); }} .trend-bar {{ display:flex; align-items:end; gap:3px; min-height:72px; padding-top:8px; }} .trend-bar span {{ flex:1; min-width:5px; background:var(--accent); opacity:.78; }} .risk-list {{ display:grid; gap:8px; }} .risk-item {{ border-left:3px solid var(--amber); padding:8px 10px; background:#171813; }} .risk-item.high,.risk-item.critical {{ border-left-color:var(--red); background:#1b1111; }} .audit-grid {{ display:grid; gap:8px; }} .audit-record pre {{ max-height:130px; }} .delta-positive {{ color:var(--accent); }} .delta-negative {{ color:var(--red); }} a {{ color:#78b9ff; overflow-wrap:anywhere; }} .artifact-missing {{ color:var(--muted); }} pre {{ white-space:pre-wrap; overflow-wrap:anywhere; max-height:180px; overflow:auto; margin:8px 0 0; padding:8px; border-left:2px solid #29403d; color:#c9d8d4; }}
    @media (max-width:780px) {{ .kpis {{ grid-template-columns:repeat(2,1fr); }} .grid {{ grid-template-columns:1fr; }} .toolbar {{ flex-direction:column; }} table {{ font-size:12px; }} }}
  </style>
</head>
<body>
  <header><div class="eyebrow">Offline reverse engineering operations</div><h1>Reverse Lab Command Deck</h1></header>
  <main>
    <section class="kpis" id="kpis"></section>
    <section class="grid">
      <div class="panel"><h2>Experiment Queue</h2><div class="toolbar"><input id="search" aria-label="Search experiments" placeholder="Search targets, IDs, notes"><select id="status" aria-label="Filter experiment status"><option value="">All statuses</option></select></div><div id="experiments"></div></div>
      <aside><div class="panel"><h2>Recommended Profiles</h2><div id="recommendations"></div></div><div class="panel"><h2>Recent Sessions</h2><div id="sessions"></div></div><div class="panel"><h2>Ingestion Diagnostics</h2><div id="diagnostics"></div></div></aside>
    </section>
    <section class="panel"><h2>Platform Core</h2><div id="platform-core"></div></section>
    <section class="panel"><h2>Model Campaign Analytics</h2><div id="campaign-analytics"></div></section>
    <section class="panel"><h2>Environment Validation</h2><div id="environment-validation"></div></section>
    <section class="panel"><h2>Analysis Domains</h2><div id="analysis-views"></div></section>
    <section class="panel"><h2>Capability Audit</h2><div id="capability-audit"></div></section>
    <section class="panel"><h2>Risk & Confidence</h2><div id="risk-highlights"></div></section>
    <section class="grid">
      <div class="panel"><h2>KnowledgeBase Recommendations</h2><div id="knowledge-recommendations"></div></div>
      <div class="panel"><h2>Session Compare & Trend</h2><div id="session-compare"></div></div>
    </section>
    <section class="panel"><h2>Artifact Navigation</h2><div id="artifact-navigation"></div></section>
    <section class="panel"><h2>Binary Patch Audit</h2><div id="binary-patches"></div></section>
    <section class="panel"><h2>Evidence Integrity</h2><div id="evidence-manifests"></div></section>
    <section class="panel source-panel"><h2>Source Reconstruction</h2><div id="source-reconstruction"></div></section>
  </main>
  <script id="dashboard-data" type="application/json">{payload}</script>
  <script>
    (() => {{
      const data = JSON.parse(document.getElementById('dashboard-data').textContent);
      const el = id => document.getElementById(id);
      const text = value => value == null || value === '' ? '---' : String(value);
      const compact = value => value && typeof value === 'object' ? JSON.stringify(value) : text(value);
      const showEmpty = (box, message) => {{ const empty=document.createElement('div'); empty.className='empty'; empty.textContent=message; box.append(empty); }};
      const summary = data.summary;
      const reconstruction = data.source_reconstruction || {{summary: {{}}, projects: []}};
      const reconstructionSummary = reconstruction.summary || {{}};
      const patches = data.binary_patches || {{count: 0, dry_run_count: 0, applied_count: 0, recent: []}};
      const evidence = data.evidence_manifests || {{count: 0, valid_count: 0, failed_count: 0, recent: []}};
      const platformCore = data.platform_core || {{status: "unavailable", cards: [], capabilities: {{}}, artifacts: {{}}}};
      const campaignAnalytics = data.campaign_analytics || {{campaign_count:0, campaigns:[], comparison:[]}};
      const analysisViews = data.analysis_views || {{}};
      const capabilityAudit = data.capability_audit || {{record_count: 0, records: [], traces: [], summary: {{}}}};
      const riskHighlights = data.risk_highlights || {{count: 0, items: []}};
      const knowledgeRecommendations = data.knowledge_recommendations || {{}};
      const sessionCompare = data.session_compare || {{available: false}};
      const sessionTrend = data.session_trend || {{point_count: 0, points: []}};
      const artifactNavigation = data.artifact_navigation || {{count: 0, groups: []}};
      const environmentValidation = data.environment_validation || {{available: false, checks: {{}}, workflows: {{}}, acceptance_fixtures: [], summary: {{}}}};
      const acceptanceHistory = data.acceptance_history || {{available: false, summary: {{}}, records: []}};
      const statusLabel = value => ({{dependency_gated:'dependency-gated', unsupported_host:'unsupported-host', repository_ready:'repository-ready', ready_to_run:'ready-to-run'}})[value] || text(value);
      const kpis = [['Experiments', summary.experiment_total], ['Completed', summary.completed_total], ['Sessions', summary.session_total], ['Verified evidence', evidence.valid_count || 0], ['Applied patches', patches.applied_count || 0], ['Source projects', reconstructionSummary.project_total || 0], ['Data warnings', data.diagnostics.malformed_json], ['Platform core', platformCore.status || 'unavailable']];
      kpis.forEach(([label,value]) => {{ const card=document.createElement('div'); card.className='kpi'; const small=document.createElement('span'); small.textContent=label; const bold=document.createElement('b'); bold.textContent=value; card.append(small,bold); el('kpis').append(card); }});
      const statuses = Object.keys(summary.status_counts).sort(); statuses.forEach(status => {{ const option=document.createElement('option'); option.value=status; option.textContent=status; el('status').append(option); }});
      function renderExperiments() {{
        const needle=el('search').value.toLowerCase(), status=el('status').value;
        const rows=data.experiments.filter(item => {{ const corpus=JSON.stringify(item).toLowerCase(); return (!needle || corpus.includes(needle)) && (!status || String(item.status || 'unknown').toLowerCase() === status); }});
        const box=el('experiments'); box.replaceChildren();
        if (!rows.length) {{ const empty=document.createElement('div'); empty.className='empty'; empty.textContent='No experiments match the current view.'; box.append(empty); return; }}
        const table=document.createElement('table'), head=document.createElement('tr'); ['Experiment','Target','Status','Updated'].forEach(label => {{ const th=document.createElement('th'); th.textContent=label; head.append(th); }}); const thead=document.createElement('thead'); thead.append(head); const body=document.createElement('tbody');
        rows.forEach(item => {{ const tr=document.createElement('tr'); const values=[item.name || item.id || item.experiment_id || item.source_file, item.target || item.sample_id || item.path, item.status || 'unknown', item.updated_at || item.timestamp || item.created_at]; values.forEach((value,index) => {{ const td=document.createElement('td'); if(index===2) {{ const badge=document.createElement('span'); badge.className='badge'; badge.textContent=text(value); td.append(badge); }} else td.textContent=text(value); tr.append(td); }}); body.append(tr); }}); table.append(thead,body); box.append(table);
      }}
      function recommendation(title, value) {{ const box=document.createElement('div'); box.className='recommendation'; const name=document.createElement('strong'); name.textContent=title; const detail=document.createElement('div'); detail.className='meta'; detail.textContent=Object.entries(value).filter(([key]) => key !== 'reason').map(([key,val]) => key + ': ' + text(val)).join(' | ') || text(value.reason); box.append(name,detail); return box; }}
      [['Dynamic profile','dynamic_profile'],['GUI strategy','gui_strategy'],['Patch strategy','patch_strategy'],['Engine strategy','engine_strategy'],['Protocol format','protocol_format'],['Source restoration','source_restoration'],['Model jailbreak strategy','llm_jailbreak_strategy']].forEach(([label,key]) => el('recommendations').append(recommendation(label, data.recommendations[key] || {{}})));
      const sessions=el('sessions'); if (!data.sessions.length) {{ sessions.innerHTML='<div class="empty">No sessions recorded.</div>'; }} else {{ const list=document.createElement('ul'); data.sessions.forEach(item => {{ const line=document.createElement('li'); line.textContent=[item.session_id || item.id || item.target || item.source_file, item.status || 'unknown', item.updated_at || item.timestamp || item.created_at].filter(Boolean).join(' | '); list.append(line); }}); sessions.append(list); }}
      const diagnostics=el('diagnostics'); diagnostics.textContent='Loaded ' + data.diagnostics.files_loaded + '/' + data.diagnostics.files_scanned + ' JSON files; malformed: ' + data.diagnostics.malformed_json + '; invalid records: ' + data.diagnostics.invalid_records + '.';

      const platformBox=el('platform-core');
      const platformCards=Array.isArray(platformCore.cards) ? platformCore.cards : [];
      if (!platformCards.length) {{ const empty=document.createElement('div'); empty.className='empty'; empty.textContent='No platform core report found yet.'; platformBox.append(empty); }} else {{
        const summary=document.createElement('div'); summary.className='source-summary'; summary.append('Status: ' + text(platformCore.status)); platformBox.append(summary);
        const cardRow=document.createElement('div'); cardRow.className='kpis'; platformCards.forEach(item => {{ const card=document.createElement('div'); card.className='kpi'; const small=document.createElement('span'); small.textContent=text(item.title); const bold=document.createElement('b'); bold.textContent=text(item.value); const sub=document.createElement('div'); sub.className='meta'; sub.textContent=text(item.subtitle); card.append(small,bold,sub); cardRow.append(card); }}); platformBox.append(cardRow);
        const caps=document.createElement('div'); caps.className='meta'; caps.textContent='Capabilities: ' + Object.entries(platformCore.capabilities || {{}}).map(([key, providers]) => key + ' (' + (providers || []).join(', ') + ')').join(' | '); platformBox.append(caps);
        const artifacts=document.createElement('div'); artifacts.className='meta'; artifacts.textContent='Artifacts: semantic_ir=' + text((platformCore.artifacts || {{}}).semantic_ir) + ' | evidence_graph=' + text((platformCore.artifacts || {{}}).evidence_graph); platformBox.append(artifacts);
        const audit=platformCore.capability_audit || {{record_count: 0, records: [], summary: {{}}}};
        const auditSummary=audit.summary || {{}};
        const auditMeta=document.createElement('div'); auditMeta.className='meta';
        const statusCounts=Object.entries(auditSummary.status_counts || {{}}).map(([key, value]) => key + '=' + text(value)).join(', ');
        auditMeta.textContent='Capability audit: records=' + text(audit.record_count || 0) + ' | rollback=' + text(auditSummary.rollback_supported_count || 0) + ' | manifests=' + text(auditSummary.manifest_reference_count || 0) + ' | traces=' + text(auditSummary.dashboard_trace_count || 0) + (statusCounts ? ' | statuses=' + statusCounts : '');
        platformBox.append(auditMeta);
        const auditRows=Array.isArray(audit.records) ? audit.records : [];
        if (auditRows.length) {{
          const details=document.createElement('details');
          const caption=document.createElement('summary');
          caption.textContent='Capability audit records (' + auditRows.length + ')';
          details.append(caption);
          const list=document.createElement('ul');
          auditRows.slice(0, 12).forEach(item => {{
            const target=item.target_identity || {{}};
            const line=document.createElement('li');
            line.textContent=[
              text(item.capability) + ':' + text(item.action),
              'provider=' + text(item.provider),
              'status=' + text(item.status),
              'target=' + text(target.display_name || target.path || target.pid || target.kind)
            ].join(' | ');
            list.append(line);
          }});
          details.append(list);
          platformBox.append(details);
        }}
      }}

      const campaignBox=el('campaign-analytics');
      const campaigns=Array.isArray(campaignAnalytics.campaigns) ? campaignAnalytics.campaigns : [];
      const campaignKpis=document.createElement('div'); campaignKpis.className='kpis';
      [['Campaigns',campaignAnalytics.campaign_count || 0],['Breakthrough rate',((Number(campaignAnalytics.breakthrough_rate || 0)*100).toFixed(1))+'%'],['Attempts',campaignAnalytics.attempt_count || 0],['Tokens',campaignAnalytics.total_tokens || 0],['Cost USD',Number(campaignAnalytics.total_cost_usd || 0).toFixed(4)]].forEach(([label,value]) => {{ const card=document.createElement('div'); card.className='kpi'; const small=document.createElement('span'); small.textContent=label; const bold=document.createElement('b'); bold.textContent=text(value); card.append(small,bold); campaignKpis.append(card); }});
      campaignBox.append(campaignKpis);
      if (!campaigns.length) {{ showEmpty(campaignBox, 'No model campaign artifacts found.'); }} else {{
        const comparison=Array.isArray(campaignAnalytics.comparison) ? campaignAnalytics.comparison : [];
        if (comparison.length) {{
          const label=document.createElement('div'); label.className='section-label'; label.textContent='Campaign comparison'; campaignBox.append(label);
          const wrap=document.createElement('div'); wrap.className='table-scroll'; const table=document.createElement('table');
          const head=document.createElement('tr'); ['Campaign','Model','Status','Attempts','Best score','Tokens','Cost USD','Latency ms','Judge','Resume'].forEach(value => {{ const th=document.createElement('th'); th.textContent=value; head.append(th); }}); const thead=document.createElement('thead'); thead.append(head); const body=document.createElement('tbody');
          comparison.forEach(item => {{ const tr=document.createElement('tr'); [item.name || item.campaign_id,item.model,item.status,item.attempt_count,item.best_score,item.total_tokens,Number(item.total_cost_usd || 0).toFixed(4),Number(item.latency_ms || 0).toFixed(1),item.judge_mode,item.resumed ? 'yes' : 'no'].forEach(value => {{ const td=document.createElement('td'); td.textContent=text(value); tr.append(td); }}); body.append(tr); }}); table.append(thead,body); wrap.append(table); campaignBox.append(wrap);
        }}
        campaigns.forEach(campaign => {{
          const card=document.createElement('article'); card.className='campaign-card';
          const title=document.createElement('h3'); title.textContent=text(campaign.name || campaign.campaign_id); card.append(title);
          const meta=document.createElement('div'); meta.className='meta'; meta.textContent=['id='+text(campaign.campaign_id),'model='+text(campaign.model),'status='+text(campaign.status),'judge='+text(campaign.judge_mode),'source='+text(campaign.source_path)].join(' | '); card.append(meta);
          const trend=Array.isArray(campaign.trend) ? campaign.trend : [];
          if (trend.length) {{ const trendLabel=document.createElement('div'); trendLabel.className='section-label'; trendLabel.textContent='Token / cost / latency trend'; card.append(trendLabel); const bars=document.createElement('div'); bars.className='campaign-grid'; trend.forEach(point => {{ const item=document.createElement('div'); item.className='trend-bar'; item.textContent='round '+text(point.round_index)+' | tokens '+text(point.cumulative_tokens)+' | $'+Number(point.cumulative_cost_usd || 0).toFixed(4)+' | '+Number(point.cumulative_latency_ms || 0).toFixed(1)+' ms'; bars.append(item); }}); card.append(bars); }}
          const tree=Array.isArray(campaign.attempt_tree) ? campaign.attempt_tree : [];
          const treeLabel=document.createElement('div'); treeLabel.className='section-label'; treeLabel.textContent='Attempt tree'; card.append(treeLabel);
          if (!tree.length) showEmpty(card, 'No detailed attempt nodes retained.'); else {{ const treeBox=document.createElement('div'); treeBox.className='attempt-tree'; tree.forEach(node => {{ const item=document.createElement('div'); item.className='attempt-node '+(node.success ? 'success' : 'failed'); item.style.marginLeft=(Math.max(0,Number(node.depth || 0))*18)+'px'; item.textContent=[text(node.candidate_id),text(node.attack_mode),text(node.strategy),'score='+text(node.score),'success='+(node.success ? 'yes' : 'no'),'tokens='+text(node.tokens),'latency='+text(node.latency_ms)+' ms'].join(' | '); treeBox.append(item); }}); card.append(treeBox); }}
          const switches=(Array.isArray(campaign.strategy_trace) ? campaign.strategy_trace : []).filter(item => item.switched);
          if (switches.length) {{ const label=document.createElement('div'); label.className='section-label'; label.textContent='Strategy switches'; card.append(label); const list=document.createElement('ul'); switches.forEach(item => {{ const line=document.createElement('li'); line.textContent='round '+text(item.round_index)+': '+text(item.from_attack_mode)+'/'+text(item.from_strategy)+' -> '+text(item.attack_mode)+'/'+text(item.strategy); list.append(line); }}); card.append(list); }}
          const verdicts=Array.isArray(campaign.judge_verdicts) ? campaign.judge_verdicts : [];
          if (verdicts.length) {{ const label=document.createElement('div'); label.className='section-label'; label.textContent='Semantic judge verdicts'; card.append(label); const list=document.createElement('ul'); verdicts.forEach(verdict => {{ const line=document.createElement('li'); line.textContent=[text(verdict.judge_name),'score='+text(verdict.score),'success='+(verdict.success ? 'yes' : 'no'),'refused='+(verdict.refused ? 'yes' : 'no'),'confidence='+text(verdict.confidence),text(verdict.rationale)].join(' | '); list.append(line); }}); card.append(list); }}
          campaignBox.append(card);
        }});
      }}

      const environmentBox=el('environment-validation');
      if (!environmentValidation.available) {{
        showEmpty(environmentBox, text(environmentValidation.reason || 'No valid environment-validation.json report found.'));
      }} else {{
        const environmentSummary=environmentValidation.summary || {{}};
        const host=environmentValidation.host || {{}};
        const environmentMeta=document.createElement('div'); environmentMeta.className='meta'; environmentMeta.textContent='Report: ' + text(environmentValidation.source_path) + ' | generated: ' + text(environmentValidation.generated_at) + ' | host: ' + text(host.system) + ' ' + text(host.machine) + ' | probes executed: ' + (environmentValidation.execute_probes ? 'yes' : 'no'); environmentBox.append(environmentMeta);
        const statusSummary=document.createElement('div'); statusSummary.className='source-summary'; [['Verified',environmentSummary.verified],['Dependency-gated',environmentSummary.dependency_gated],['Partial',environmentSummary.partial],['Failed',environmentSummary.failed],['Unavailable',environmentSummary.unavailable],['Unsupported host',environmentSummary.unsupported_host]].forEach(([label,value]) => {{ const item=document.createElement('span'); item.textContent=label + ': ' + text(value || 0); statusSummary.append(item); }}); environmentBox.append(statusSummary);

        const checks=Object.entries(environmentValidation.checks || {{}});
        const checksLabel=document.createElement('div'); checksLabel.className='section-label'; checksLabel.textContent='Dependency checks'; environmentBox.append(checksLabel);
        if (!checks.length) {{ showEmpty(environmentBox, 'No dependency checks recorded.'); }} else {{
          const wrap=document.createElement('div'); wrap.className='table-scroll';
          const table=document.createElement('table'), head=document.createElement('tr'); ['Dependency','Kind','Discovery','Probe verification','Location'].forEach(label => {{ const th=document.createElement('th'); th.textContent=label; head.append(th); }}); const thead=document.createElement('thead'); thead.append(head); const body=document.createElement('tbody');
          checks.forEach(([name,item]) => {{ const tr=document.createElement('tr'); const discovery=item.discovered === true ? 'discovered' : 'unavailable'; const probeStatus=item.status === 'verified' ? 'verified' : (item.status === 'failed' ? 'failed' : 'not-executed'); const values=[name,item.kind,discovery,probeStatus,item.path || item.module || item.value || item.env]; values.forEach((value,index) => {{ const td=document.createElement('td'); if(index === 2 || index === 3) {{ const badge=document.createElement('span'); badge.className='badge'; badge.textContent=statusLabel(value); td.append(badge); }} else td.textContent=text(value); tr.append(td); }}); body.append(tr); }}); table.append(thead,body); wrap.append(table); environmentBox.append(wrap);
        }}

        const workflows=Object.entries(environmentValidation.workflows || {{}});
        const workflowsLabel=document.createElement('div'); workflowsLabel.className='section-label'; workflowsLabel.textContent='Workflow readiness'; environmentBox.append(workflowsLabel);
        if (!workflows.length) {{ showEmpty(environmentBox, 'No workflow readiness records found.'); }} else {{
          const wrap=document.createElement('div'); wrap.className='table-scroll';
          const table=document.createElement('table'), head=document.createElement('tr'); ['Workflow','Status','Ready','Dependencies','Boundary'].forEach(label => {{ const th=document.createElement('th'); th.textContent=label; head.append(th); }}); const thead=document.createElement('thead'); thead.append(head); const body=document.createElement('tbody');
          workflows.forEach(([name,item]) => {{ const tr=document.createElement('tr'); const required=Array.isArray(item.required) ? item.required.join(', ') : ''; const anyOf=Array.isArray(item.any_of) && item.any_of.length ? 'any: ' + item.any_of.join(', ') : ''; const dependencies=[required,anyOf].filter(Boolean).join(' | '); const values=[name,item.status,item.ready ? 'yes' : 'no',dependencies,item.note]; values.forEach((value,index) => {{ const td=document.createElement('td'); if(index === 1) {{ const badge=document.createElement('span'); badge.className='badge'; badge.textContent=statusLabel(value); td.append(badge); }} else td.textContent=text(value); tr.append(td); }}); body.append(tr); }}); table.append(thead,body); wrap.append(table); environmentBox.append(wrap);
        }}

        const fixtures=Array.isArray(environmentValidation.acceptance_fixtures) ? environmentValidation.acceptance_fixtures : [];
        const fixturesLabel=document.createElement('div'); fixturesLabel.className='section-label'; fixturesLabel.textContent='Acceptance fixtures'; environmentBox.append(fixturesLabel);
        const fixtureSummary=document.createElement('div'); fixtureSummary.className='source-summary'; [['Repository-ready',environmentSummary.acceptance_fixture_repository_ready],['Ready-to-run',environmentSummary.acceptance_fixture_ready_to_run],['Dependency-gated',environmentSummary.acceptance_fixture_dependency_gated],['Unsupported host',environmentSummary.acceptance_fixture_unsupported_host],['Live verified',fixtures.filter(item => item.live_verified === true).length]].forEach(([label,value]) => {{ const item=document.createElement('span'); item.textContent=label + ': ' + text(value || 0); fixtureSummary.append(item); }}); environmentBox.append(fixtureSummary);
        if (!fixtures.length) {{ showEmpty(environmentBox, 'No acceptance fixtures recorded.'); }} else {{
          const wrap=document.createElement('div'); wrap.className='table-scroll';
          const table=document.createElement('table'), head=document.createElement('tr'); ['Phase','Capability / fixture','Status','Evidence level','Missing gates','Acceptance command'].forEach(label => {{ const th=document.createElement('th'); th.textContent=label; head.append(th); }}); const thead=document.createElement('thead'); thead.append(head); const body=document.createElement('tbody');
          fixtures.forEach(item => {{ const tr=document.createElement('tr'); const missing=Array.isArray(item.missing_gates) ? item.missing_gates.join(', ') : ''; const identity=[item.capability,item.id].filter(Boolean).join(' / '); const status=item.live_verified === true ? 'live-verified' : statusLabel(item.status); const values=[item.phase,identity,status,item.evidence_level,missing,item.command]; values.forEach((value,index) => {{ const td=document.createElement('td'); if(index === 2) {{ const badge=document.createElement('span'); badge.className='badge'; badge.textContent=text(value); td.append(badge); }} else td.textContent=text(value); tr.append(td); }}); body.append(tr); }}); table.append(thead,body); wrap.append(table); environmentBox.append(wrap);
        }}
      }}

      const acceptanceLabel=document.createElement('div'); acceptanceLabel.className='section-label'; acceptanceLabel.textContent='Acceptance history'; environmentBox.append(acceptanceLabel);
      const acceptanceSummary=acceptanceHistory.summary || {{}};
      const acceptanceStats=document.createElement('div'); acceptanceStats.className='source-summary'; [['Runs',acceptanceSummary.total],['Live verified',acceptanceSummary.live_verified],['Failed',acceptanceSummary.failed],['Dependency blocked',acceptanceSummary.dependency_blocked]].forEach(([label,value]) => {{ const item=document.createElement('span'); item.textContent=label + ': ' + text(value || 0); acceptanceStats.append(item); }}); environmentBox.append(acceptanceStats);
      const acceptanceRecords=Array.isArray(acceptanceHistory.records) ? acceptanceHistory.records : [];
      if (!acceptanceRecords.length) {{ showEmpty(environmentBox, 'No acceptance run records found under acceptance/records.'); }} else {{
        const wrap=document.createElement('div'); wrap.className='table-scroll';
        const table=document.createElement('table'), head=document.createElement('tr'); ['Phase','Fixture / capability','Outcome','Live proof','Started / finished','Artifacts'].forEach(label => {{ const th=document.createElement('th'); th.textContent=label; head.append(th); }}); const thead=document.createElement('thead'); thead.append(head); const body=document.createElement('tbody');
        acceptanceRecords.forEach(item => {{
          const tr=document.createElement('tr');
          const phase=document.createElement('td'); phase.textContent=text(item.phase); tr.append(phase);
          const identity=document.createElement('td'); identity.textContent=[item.fixture_id,item.capability].filter(Boolean).join(' / '); tr.append(identity);
          const outcome=document.createElement('td'); const outcomeBadge=document.createElement('span'); outcomeBadge.className='badge'; outcomeBadge.textContent=statusLabel(item.outcome); outcome.append(outcomeBadge); tr.append(outcome);
          const live=document.createElement('td'); const liveBadge=document.createElement('span'); liveBadge.className='badge'; liveBadge.textContent=item.live_verified === true ? 'live-verified' : 'not-live-verified'; live.append(liveBadge); tr.append(live);
          const timing=document.createElement('td'); timing.textContent=text(item.started_at) + ' / ' + text(item.finished_at); tr.append(timing);
          const artifactCell=document.createElement('td'); const links=Array.isArray(item.artifact_links) ? item.artifact_links : []; if (!links.length) {{ artifactCell.textContent='none'; }} else {{ const list=document.createElement('ul'); links.forEach(entry => {{ const line=document.createElement('li'); if(entry.exists && entry.href) {{ const link=document.createElement('a'); link.href=entry.href; link.textContent=text(entry.label || entry.path); link.title=text(entry.path); line.append(link); }} else {{ const missing=document.createElement('span'); missing.className='artifact-missing'; missing.textContent=text(entry.label || entry.path) + ' [missing]'; line.append(missing); }} list.append(line); }}); artifactCell.append(list); }} tr.append(artifactCell);
          body.append(tr);
        }});
        table.append(thead,body); wrap.append(table); environmentBox.append(wrap);
      }}

      const analysisBox=el('analysis-views');
      const domainViews=Object.values(analysisViews);
      if (!domainViews.length) {{ showEmpty(analysisBox, 'No analysis-domain reports found.'); }} else {{
        const grid=document.createElement('div'); grid.className='analysis-grid';
        domainViews.forEach(view => {{
          const card=document.createElement('article'); card.className='analysis-card' + (view.low_confidence ? ' is-low' : '');
          const title=document.createElement('h3'); title.textContent=text(view.title || view.domain);
          const state=document.createElement('span'); state.className='badge'; state.textContent=text(view.status || 'unavailable');
          const head=document.createElement('div'); head.className='source-head'; head.append(title,state); card.append(head);
          const meta=document.createElement('div'); meta.className='meta'; meta.textContent='confidence=' + text(view.confidence) + ' | reports=' + text(view.history_count || 0) + ' | artifacts=' + text(view.artifact_count || 0); card.append(meta);
          const metrics=Array.isArray(view.metrics) ? view.metrics : [];
          if (metrics.length) {{ const list=document.createElement('ul'); metrics.forEach(metric => {{ const line=document.createElement('li'); line.textContent=text(metric.label) + ': ' + compact(metric.value); list.append(line); }}); card.append(list); }}
          if (view.strategy != null) {{ const strategy=document.createElement('div'); strategy.className='meta'; strategy.textContent='Strategy: ' + compact(view.strategy); card.append(strategy); }}
          if (view.report_source) {{ const source=document.createElement('div'); source.className='meta'; source.textContent='Report: ' + text(view.report_source); card.append(source); }}
          grid.append(card);
        }});
        analysisBox.append(grid);
      }}

      const capabilityBox=el('capability-audit');
      const capabilityRows=Array.isArray(capabilityAudit.records) ? capabilityAudit.records : [];
      const capabilitySummary=capabilityAudit.summary || {{}};
      const capabilityMeta=document.createElement('div'); capabilityMeta.className='meta'; capabilityMeta.textContent='Records: ' + text(capabilityAudit.record_count || 0) + ' | traces: ' + text(capabilityAudit.trace_count || 0) + ' | rollback: ' + text(capabilitySummary.rollback_supported_count || 0) + ' | preconditions: ' + text(capabilitySummary.precondition_hash_count || 0) + ' | before/after snapshots: ' + text(capabilitySummary.before_snapshot_count || 0) + '/' + text(capabilitySummary.after_snapshot_count || 0) + ' | events: ' + text(capabilitySummary.event_count || 0); capabilityBox.append(capabilityMeta);
      if (!capabilityRows.length) {{ showEmpty(capabilityBox, 'No capability audit records found in reports.'); }} else {{
        const grid=document.createElement('div'); grid.className='audit-grid';
        capabilityRows.forEach(item => {{
          const card=document.createElement('article'); card.className='audit-record';
          const head=document.createElement('div'); head.className='source-head'; const name=document.createElement('strong'); name.textContent=text(item.capability) + ':' + text(item.action); const state=document.createElement('span'); state.className='badge'; state.textContent=text(item.status); head.append(name,state); card.append(head);
          const target=document.createElement('div'); target.className='meta'; target.textContent='session=' + text(item.session_id) + ' | provider=' + text(item.provider) + ' | target=' + compact(item.target_identity) + ' | report_section=' + text(item.report_section); card.append(target);
          const integrity=document.createElement('div'); integrity.className='meta'; integrity.textContent='precondition=' + text(item.precondition_hash) + ' | rollback=' + text(Boolean(item.rollback_plan || item.rollback_supported)) + ' | manifest=' + text(Boolean(item.evidence_manifest_entries)); card.append(integrity);
          const detailPayload={{before_snapshot:item.before_snapshot,after_snapshot:item.after_snapshot,rollback_plan:item.rollback_plan,provenance:item.provenance,events:item.events,dashboard_trace:item.dashboard_trace}};
          if (Object.values(detailPayload).some(value => value != null)) {{ const details=document.createElement('details'); const caption=document.createElement('summary'); caption.textContent='Audit evidence and dashboard trace'; const pre=document.createElement('pre'); pre.textContent=JSON.stringify(detailPayload,null,2); details.append(caption,pre); card.append(details); }}
          grid.append(card);
        }});
        capabilityBox.append(grid);
      }}

      const riskBox=el('risk-highlights');
      const risks=Array.isArray(riskHighlights.items) ? riskHighlights.items : [];
      if (!risks.length) {{ showEmpty(riskBox, 'No high-risk or low-confidence report results.'); }} else {{
        const meta=document.createElement('div'); meta.className='meta'; meta.textContent='Risks: ' + text(riskHighlights.risk_count || 0) + ' | low confidence: ' + text(riskHighlights.low_confidence_count || 0) + ' | threshold: ' + text(riskHighlights.low_confidence_threshold); riskBox.append(meta);
        const list=document.createElement('div'); list.className='risk-list'; risks.forEach(item => {{ const row=document.createElement('div'); row.className='risk-item ' + text(item.severity).toLowerCase(); const title=document.createElement('strong'); title.textContent='[' + text(item.severity) + '] ' + text(item.title); const detail=document.createElement('div'); detail.className='meta'; detail.textContent=[item.domain,item.detail,item.confidence != null ? 'confidence=' + item.confidence : null,item.report_source].filter(Boolean).join(' | '); row.append(title,detail); list.append(row); }}); riskBox.append(list);
      }}

      const knowledgeBox=el('knowledge-recommendations');
      const learned=Object.values(knowledgeRecommendations);
      if (!learned.length) {{ showEmpty(knowledgeBox, 'No KnowledgeBase stores found.'); }} else {{ learned.forEach(item => {{ const node=recommendation(text(item.label), item.recommendation || {{}}); const stats=document.createElement('div'); stats.className='meta'; stats.textContent='Candidates: ' + text(item.candidate_count || 0) + ' | accumulated runs: ' + text(item.total_runs || 0); node.append(stats); knowledgeBox.append(node); }}); }}

      const compareBox=el('session-compare');
      const trendMeta=document.createElement('div'); trendMeta.className='meta'; trendMeta.textContent='Sessions: ' + text(sessionTrend.point_count || 0) + ' | completion rate: ' + text(sessionTrend.completion_rate || 0) + ' | statuses: ' + Object.entries(sessionTrend.status_counts || {{}}).map(([key,value]) => key + '=' + value).join(', '); compareBox.append(trendMeta);
      if (!sessionCompare.available) {{ showEmpty(compareBox, text(sessionCompare.reason || 'No session comparison available.')); }} else {{
        const latest=sessionCompare.latest || {{}}, previous=sessionCompare.previous || {{}};
        const pair=document.createElement('div'); pair.className='source-summary'; pair.append('Latest: ' + text(latest.session_id) + ' (' + text(latest.status) + ')', 'Previous: ' + text(previous.session_id) + ' (' + text(previous.status) + ')'); compareBox.append(pair);
        const deltas=document.createElement('ul'); Object.entries(sessionCompare.deltas || {{}}).forEach(([key,value]) => {{ const line=document.createElement('li'); line.className=Number(value) > 0 ? 'delta-positive' : (Number(value) < 0 ? 'delta-negative' : ''); line.textContent=key + ': ' + (Number(value) > 0 ? '+' : '') + text(value); deltas.append(line); }}); compareBox.append(deltas);
        const changes=Array.isArray(sessionCompare.recommendation_changes) ? sessionCompare.recommendation_changes : [];
        if (changes.length) {{ const details=document.createElement('details'); const caption=document.createElement('summary'); caption.textContent='Recommendation changes (' + changes.length + ')'; const list=document.createElement('ul'); changes.forEach(item => {{ const line=document.createElement('li'); line.textContent=text(item.namespace) + ': ' + text(item.previous) + ' -> ' + text(item.latest); list.append(line); }}); details.append(caption,list); compareBox.append(details); }}
      }}

      const artifactBox=el('artifact-navigation');
      const artifactGroups=Array.isArray(artifactNavigation.groups) ? artifactNavigation.groups : [];
      const artifactMeta=document.createElement('div'); artifactMeta.className='meta'; artifactMeta.textContent='References: ' + text(artifactNavigation.count || 0) + ' | available: ' + text(artifactNavigation.available_count || 0) + ' | missing: ' + text(artifactNavigation.missing_count || 0) + ' | blocked outside workspace: ' + text(artifactNavigation.blocked_count || 0); artifactBox.append(artifactMeta);
      if (!artifactGroups.length) {{ showEmpty(artifactBox, 'No workspace artifacts referenced by reports or sessions.'); }} else {{
        const grid=document.createElement('div'); grid.className='artifact-grid'; artifactGroups.forEach(group => {{ const card=document.createElement('article'); card.className='artifact-group'; const title=document.createElement('h3'); title.textContent=text(group.domain) + ' (' + text(group.available_count) + '/' + text(group.count) + ')'; card.append(title); const list=document.createElement('ul'); (group.items || []).forEach(item => {{ const line=document.createElement('li'); if (item.exists && item.href) {{ const link=document.createElement('a'); link.href=item.href; link.textContent=text(item.label || item.path); link.title=text(item.path); line.append(link); }} else {{ const missing=document.createElement('span'); missing.className='artifact-missing'; missing.textContent=text(item.label || item.path) + ' [missing]'; line.append(missing); }} list.append(line); }}); card.append(list); grid.append(card); }}); artifactBox.append(grid);
      }}

      const patchBox=el('binary-patches'); const patchRows=Array.isArray(patches.recent) ? patches.recent : [];
      if (!patchRows.length) {{ const empty=document.createElement('div'); empty.className='empty'; empty.textContent='No binary patch manifests found in sessions or output artifacts.'; patchBox.append(empty); }} else {{
        const summary=document.createElement('div'); summary.className='meta'; summary.textContent='Audited: ' + text(patches.count) + ' | applied: ' + text(patches.applied_count) + ' | dry runs: ' + text(patches.dry_run_count); patchBox.append(summary);
        const table=document.createElement('table'), head=document.createElement('tr'); ['Action','Input ? output','Hashes','Operations','Status','Timestamp'].forEach(label => {{ const th=document.createElement('th'); th.textContent=label; head.append(th); }}); const thead=document.createElement('thead'); thead.append(head); const body=document.createElement('tbody');
        patchRows.forEach(item => {{ const tr=document.createElement('tr'); const values=[item.audit_type || 'patch', [text(item.source_path), text(item.patched_path)].join(' ? '), [text(item.source_sha256), text(item.patched_sha256)].join(' ? '), item.operation_count, item.dry_run ? 'dry run' : (item.status || 'unknown'), item.timestamp]; values.forEach((value,index) => {{ const td=document.createElement('td'); if(index===0 || index===4) {{ const badge=document.createElement('span'); badge.className='badge'; badge.textContent=text(value); td.append(badge); }} else td.textContent=text(value); tr.append(td); }}); body.append(tr); }}); table.append(thead,body); patchBox.append(table);
      }}
      const evidenceBox=el('evidence-manifests'); const evidenceRows=Array.isArray(evidence.recent) ? evidence.recent : [];
      if (!evidenceRows.length) {{ const empty=document.createElement('div'); empty.className='empty'; empty.textContent='No evidence manifests found. Run analyze to create a portable verification package.'; evidenceBox.append(empty); }} else {{
        const summary=document.createElement('div'); summary.className='meta'; summary.textContent='Packages: ' + text(evidence.count) + ' | valid: ' + text(evidence.valid_count) + ' | failed: ' + text(evidence.failed_count) + ' | verified files: ' + text(evidence.verified_file_count); evidenceBox.append(summary);
        const table=document.createElement('table'), head=document.createElement('tr'); ['Manifest','Status','Files','Unavailable','Issues'].forEach(label => {{ const th=document.createElement('th'); th.textContent=label; head.append(th); }}); const thead=document.createElement('thead'); thead.append(head); const body=document.createElement('tbody');
        evidenceRows.forEach(item => {{ const tr=document.createElement('tr'); const values=[item.manifest_path, item.status || 'unknown', text(item.verified_file_count) + '/' + text(item.covered_file_count), item.unavailable_stage_count, item.issue_count ? item.issue_count + ' (' + (item.issue_kinds || []).join(', ') + ')' : '0']; values.forEach((value,index) => {{ const td=document.createElement('td'); if(index===1) {{ const badge=document.createElement('span'); badge.className='badge'; badge.textContent=text(value); td.append(badge); }} else td.textContent=text(value); tr.append(td); }}); body.append(tr); }}); table.append(thead,body); evidenceBox.append(table);
      }}
      const reconstructionBox=el('source-reconstruction');
      const projects=Array.isArray(reconstruction.projects) ? reconstruction.projects : [];
      const reconstructionBoundary=document.createElement('div'); reconstructionBoundary.className='evidence-boundary'; reconstructionBoundary.textContent='Complete behavior proof: not claimed | Claim scope: differential/static/runtime observations only'; reconstructionBox.append(reconstructionBoundary);
      if (!projects.length) {{ const empty=document.createElement('div'); empty.className='empty'; empty.textContent='No reconstructed source projects discovered yet. Run analyze with --reconstruct or --reconstruct-gui.'; reconstructionBox.append(empty); }} else {{
        const sourceSummary=document.createElement('div'); sourceSummary.className='source-summary';
        [['Projects', reconstructionSummary.project_total], ['Source files', reconstructionSummary.source_file_total], ['Resources', reconstructionSummary.resource_file_total], ['Recovered functions', reconstructionSummary.function_total], ['Dynamic evidence', reconstructionSummary.dynamic_evidence_total], ['Semantic entities', reconstructionSummary.semantic_entity_total], ['Evidence assessments', reconstructionSummary.equivalence_assessment_project_total], ['Observed matches', reconstructionSummary.observed_evidence_matched_project_total]].forEach(([label,value]) => {{ const item=document.createElement('span'); item.textContent=label + ': ' + text(value || 0); sourceSummary.append(item); }});
        reconstructionBox.append(sourceSummary);
        projects.forEach(project => {{
          const card=document.createElement('article'); card.className='source-project';
          const head=document.createElement('div'); head.className='source-head'; const name=document.createElement('strong'); name.textContent=text(project.name || project.relative_path || 'reconstructed project'); const state=document.createElement('span'); state.className='badge'; state.textContent=text(project.status || project.output_stack || project.language || 'discovered'); head.append(name,state); card.append(head);
          const location=document.createElement('div'); location.className='meta'; location.textContent=text(project.relative_path || project.project_dir || project.path); card.append(location);
          const assessment=project.equivalence_assessment && typeof project.equivalence_assessment === 'object' ? project.equivalence_assessment : {{}};
          const assessmentStatus=project.equivalence_assessment_status || assessment.status || 'unverified';
          const observedStatus=project.observed_evidence_matched === true ? 'matched' : (assessmentStatus === 'mismatch' ? 'mismatch' : 'unverified');
          const assessmentScore=project.equivalence_assessment_score != null ? project.equivalence_assessment_score : assessment.score;
          const mismatchCount=Number(project.equivalence_mismatch_count != null ? project.equivalence_mismatch_count : (assessment.mismatch_count || 0));
          const metrics=document.createElement('div'); metrics.className='source-metrics'; [['Language', project.language || project.output_stack], ['Source files', project.source_file_count], ['Resources', project.resource_file_count], ['Functions', project.function_count], ['Modules', project.module_count], ['Evidence', project.dynamic_evidence_count], ['Semantic', project.semantic_entity_count], ['Assessment', statusLabel(assessmentStatus)], ['Evidence score', assessmentScore], ['Mismatches', mismatchCount], ['Next', project.next_task]].forEach(([label,value]) => {{ if(value != null && value !== '') {{ const item=document.createElement('span'); item.textContent=label + ': ' + text(value); metrics.append(item); }} }}); card.append(metrics);
          const boundary=document.createElement('div'); boundary.className='evidence-boundary'; boundary.textContent='Observed evidence: ' + statusLabel(observedStatus) + ' | Complete behavior proof: not claimed | Claim scope: differential/static/runtime observations only'; card.append(boundary);

          const dimensionDetails=document.createElement('details'); const dimensionCaption=document.createElement('summary'); const dimensionStatuses=project.equivalence_dimension_statuses && typeof project.equivalence_dimension_statuses === 'object' ? project.equivalence_dimension_statuses : Object.fromEntries(Object.entries(assessment.dimensions || {{}}).map(([key,value]) => [key,value && value.status ? value.status : 'unverified'])); const dimensions=Object.entries(dimensionStatuses); dimensionCaption.textContent='Dimensions (' + dimensions.length + ')'; dimensionDetails.append(dimensionCaption); if (!dimensions.length) {{ const empty=document.createElement('div'); empty.className='meta'; empty.textContent='No observed dimension evidence.'; dimensionDetails.append(empty); }} else {{ const list=document.createElement('ul'); dimensions.forEach(([dimension,status]) => {{ const detail=(assessment.dimensions || {{}})[dimension] || {{}}; const line=document.createElement('li'); line.textContent=dimension + ': ' + statusLabel(status) + (detail.score != null ? ' | score=' + text(detail.score) : ''); list.append(line); }}); dimensionDetails.append(list); }} card.append(dimensionDetails);

          const mismatchDetails=document.createElement('details'); const mismatchCaption=document.createElement('summary'); mismatchCaption.textContent='Mismatches (' + text(mismatchCount) + ')'; mismatchDetails.append(mismatchCaption); const mismatches=Array.isArray(assessment.mismatches) ? assessment.mismatches : []; if (!mismatches.length) {{ const empty=document.createElement('div'); empty.className='meta'; empty.textContent='No observed mismatch records.'; mismatchDetails.append(empty); }} else {{ const list=document.createElement('ul'); mismatches.slice(0, 24).forEach(item => {{ const entities=Array.isArray(item.semantic_ir_entity_ids) ? item.semantic_ir_entity_ids.join(', ') : ''; const line=document.createElement('li'); line.textContent=[item.dimension,item.observation_id || item.id,entities ? 'entities=' + entities : null].filter(Boolean).map(text).join(' | '); list.append(line); }}); mismatchDetails.append(list); }} card.append(mismatchDetails);
          const files=Array.isArray(project.source_files) ? project.source_files : [];
          if (files.length) {{ const details=document.createElement('details'); const caption=document.createElement('summary'); caption.textContent='Recovered source files (' + files.length + ')'; details.append(caption); const fileGrid=document.createElement('div'); fileGrid.className='source-files'; files.slice(0, 24).forEach(file => {{ const item=document.createElement('div'); item.className='source-file'; const path=document.createElement('strong'); path.textContent=text(file.path || file.relative_path || file.name); const info=document.createElement('div'); info.className='meta'; info.textContent=[file.language, file.size_bytes != null ? file.size_bytes + ' B' : null].filter(Boolean).join(' | '); item.append(path,info); if(file.preview) {{ const preview=document.createElement('pre'); preview.textContent=text(file.preview); item.append(preview); }} fileGrid.append(item); }}); details.append(fileGrid); card.append(details); }}
          reconstructionBox.append(card);
        }});
      }}
      el('search').addEventListener('input', renderExperiments); el('status').addEventListener('change', renderExperiments); renderExperiments();
    }})();
  </script>
</body>
</html>
"""
