"""Bounded model feedback loop for behavioral mismatches."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any

from .build_repair import collect_build_diagnostics


BEHAVIOR_REPAIR_SCHEMA_VERSION = 1
DEFAULT_BEHAVIOR_REPAIR_PATH = Path("docs/behavior-repair-loop.json")
DEFAULT_BEHAVIOR_REPAIR_DIRECTORY = Path("docs/behavior-repair")
DEFAULT_MAX_ITERATIONS = 3
MAX_ITERATIONS = 20
MAX_DIAGNOSTIC_BYTES = 256 * 1024
MAX_DIAGNOSTIC_BYTES_PER_ITERATION = 64 * 1024
DEFAULT_MAX_TOKEN_BUDGET = 128_000
MAX_TOKEN_BUDGET = 2_000_000


def run_behavior_repair_loop(
    project_dir: str | os.PathLike[str],
    initial_behavior_result: Mapping[str, Any],
    behavior_spec: Mapping[str, Any] | str | os.PathLike[str] | None,
    repair_callback: Callable[..., Mapping[str, Any]],
    rebuild_callback: Callable[[Path], Mapping[str, Any]],
    revalidate_callback: Callable[[Path], Mapping[str, Any]],
    *,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    max_diagnostic_bytes: int = MAX_DIAGNOSTIC_BYTES,
    max_token_budget: int = DEFAULT_MAX_TOKEN_BUDGET,
) -> dict[str, Any]:
    """Repair, rebuild and revalidate a real behavior mismatch within hard bounds."""

    root = Path(project_dir).resolve()
    started = time.monotonic()
    result_path = root / DEFAULT_BEHAVIOR_REPAIR_PATH
    evidence_root = root / DEFAULT_BEHAVIOR_REPAIR_DIRECTORY
    current_behavior = _plain_mapping(initial_behavior_result, "behavior result")
    bounded_iterations = _bounded(max_iterations, MAX_ITERATIONS, "max_iterations")
    bounded_diagnostics = _bounded(max_diagnostic_bytes, MAX_DIAGNOSTIC_BYTES, "max_diagnostic_bytes")
    bounded_tokens = _bounded(max_token_budget, MAX_TOKEN_BUDGET, "max_token_budget")
    result: dict[str, Any] = {
        "schema_version": BEHAVIOR_REPAIR_SCHEMA_VERSION,
        "status": "dependency-gated",
        "passed": False,
        "started_at": _utc_now(),
        "finished_at": None,
        "duration_ms": 0,
        "project_dir": str(root),
        "max_iterations": bounded_iterations,
        "max_diagnostic_bytes": bounded_diagnostics,
        "max_token_budget": bounded_tokens,
        "iterations_completed": 0,
        "call_count": 0,
        "diagnostic_bytes_consumed": 0,
        "attempted_applied_change_count": 0,
        "applied_change_count": 0,
        "blocking_reasons": [],
        "iterations": [],
        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        "final_build_result": None,
        "final_behavior_result": current_behavior,
        "artifacts": {
            "loop": DEFAULT_BEHAVIOR_REPAIR_PATH.as_posix(),
            "iterations": DEFAULT_BEHAVIOR_REPAIR_DIRECTORY.as_posix(),
            "final_build": None,
            "final_behavior": None,
        },
    }

    if behavior_spec is None:
        return _gate(result, result_path, started, "behavior_validation_spec_required")
    if _strict_behavior_passed(current_behavior):
        result["status"] = "passed"
        result["passed"] = True
        return _finish(result, result_path, started)
    if not _repairable_mismatch(current_behavior):
        return _gate(result, result_path, started, "behavior_mismatch_evidence_required")
    if not is_strict_real_behavior_mismatch(current_behavior):
        return _gate(result, result_path, started, "strict_real_behavior_mismatch_required")
    if bounded_iterations == 0:
        result["status"] = "exhausted"
        result["blocking_reasons"].append("behavior_repair_iteration_budget_exhausted")
        return _finish(result, result_path, started)

    previous_repair_error: str | None = None
    for iteration in range(1, bounded_iterations + 1):
        if int(result["usage"]["total_tokens"]) >= bounded_tokens:
            result["status"] = "exhausted"
            result["blocking_reasons"].append("behavior_repair_token_budget_exhausted")
            break
        remaining = bounded_diagnostics - int(result["diagnostic_bytes_consumed"])
        if remaining <= 0:
            result["status"] = "exhausted"
            result["blocking_reasons"].append("behavior_repair_diagnostic_budget_exhausted")
            break

        behavior_diff, diagnostics = _behavior_diff(
            current_behavior,
            min(remaining, MAX_DIAGNOSTIC_BYTES_PER_ITERATION),
        )
        if previous_repair_error:
            behavior_diff["previous_repair_error"] = previous_repair_error
            diagnostics += f"\nPrevious repair was rejected: {previous_repair_error}"
        if not behavior_diff["comparisons"]:
            return _gate(result, result_path, started, "behavior_mismatch_evidence_required")
        diagnostic_bytes = len(diagnostics.encode("utf-8"))
        result["diagnostic_bytes_consumed"] += diagnostic_bytes
        iteration_root = evidence_root / f"iteration-{iteration}"
        iteration_root.mkdir(parents=True, exist_ok=True)
        before_path = iteration_root / "behavior-before.json"
        repair_path = iteration_root / "model-repair.json"
        build_path = iteration_root / "build-result.json"
        after_path = iteration_root / "behavior-after.json"
        _write_json(before_path, current_behavior)
        result["artifacts"]["final_behavior"] = before_path.relative_to(root).as_posix()
        _write_json(repair_path, {"status": "not-run", "reason": "model_repair_pending"})
        _write_json(build_path, {"status": "not-run", "reason": "model_repair_pending"})
        _write_json(after_path, {"status": "not-run", "reason": "successful_isolated_build_required"})
        record: dict[str, Any] = {
            "iteration": iteration,
            "status": "repairing",
            "diagnostic_bytes": diagnostic_bytes,
            "diagnostic_context_bytes": diagnostic_bytes,
            "behavior_before": before_path.relative_to(root).as_posix(),
            "model_repair": repair_path.relative_to(root).as_posix(),
            "build_result": build_path.relative_to(root).as_posix(),
            "behavior_after": after_path.relative_to(root).as_posix(),
            "attempted_applied_change_count": 0,
            "committed_applied_change_count": 0,
            "evidence_refresh": None,
            "error": None,
        }
        result["iterations"].append(record)
        source_snapshot = _snapshot_target_files(root)
        remaining_token_budget = bounded_tokens - int(result["usage"]["total_tokens"])

        try:
            raw_repair = repair_callback(
                project_dir=root,
                iteration=iteration,
                diagnostics=diagnostics,
                behavior_diff=behavior_diff,
                diagnostic_context_bytes=diagnostic_bytes,
                remaining_token_budget=remaining_token_budget,
            )
        except Exception as error:
            rollback_result = _rollback_and_check(
                result, record, root, source_snapshot, result_path, started,
                "behavior_repair_model_unavailable",
            )
            if rollback_result is not None:
                return rollback_result
            record["status"] = "failed"
            record["error"] = f"{type(error).__name__}: {error}"
            _write_json(repair_path, {"status": "failed", "error": record["error"]})
            return _gate(result, result_path, started, "behavior_repair_model_unavailable")
        try:
            repair = _normalize_repair(raw_repair)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            rollback_result = _rollback_and_check(
                result, record, root, source_snapshot, result_path, started,
                "behavior_repair_model_invalid",
            )
            if rollback_result is not None:
                return rollback_result
            record["status"] = "dependency-gated"
            record["error"] = f"{type(error).__name__}: {error}"
            _write_json(repair_path, {"status": "failed", "error": record["error"]})
            return _gate(result, result_path, started, "behavior_repair_model_invalid")
        try:
            _write_json(repair_path, repair)
            record["model_repair"] = repair_path.relative_to(root).as_posix()
            _merge_usage(result["usage"], repair["usage"])
            result["call_count"] += repair["call_count"]
            if repair["usage"]["total_tokens"] > remaining_token_budget:
                rollback_result = _rollback_and_check(result, record, root, source_snapshot, result_path, started, "behavior_repair_token_budget_exceeded")
                if rollback_result is not None:
                    return rollback_result
                record["status"] = "exhausted"
                result["iterations_completed"] = iteration
                result["status"] = "exhausted"
                result["blocking_reasons"].append("behavior_repair_token_budget_exceeded")
                return _finish(result, result_path, started)
            if repair["status"] == "failed" or repair["error"]:
                if (
                    repair["error_kind"] == "invalid_response"
                    and "must change at least one source file" in repair["error"]
                    and iteration < bounded_iterations
                ):
                    rollback_result = _rollback_and_check(result, record, root, source_snapshot, result_path, started, "behavior_repair_model_invalid")
                    if rollback_result is not None:
                        return rollback_result
                    record["status"] = "retrying"
                    record["error"] = repair["error"]
                    result["iterations_completed"] = iteration
                    previous_repair_error = repair["error"]
                    continue
                model_reason = (
                    "behavior_repair_model_unavailable"
                    if repair["error_kind"] == "provider_unavailable"
                    else "behavior_repair_model_invalid"
                )
                rollback_result = _rollback_and_check(result, record, root, source_snapshot, result_path, started, model_reason)
                if rollback_result is not None:
                    return rollback_result
                record["status"] = "dependency-gated"
                record["error"] = repair["error"] or "model response was invalid"
                return _gate(result, result_path, started, model_reason)
            attempted_count = len(repair["applied_changes"])
            record["attempted_applied_change_count"] = attempted_count
            result["attempted_applied_change_count"] += attempted_count
            if not repair["applied_changes"]:
                rollback_result = _rollback_and_check(result, record, root, source_snapshot, result_path, started, "behavior_repair_produced_no_applied_changes")
                if rollback_result is not None:
                    return rollback_result
                record["status"] = "dependency-gated"
                return _gate(result, result_path, started, "behavior_repair_produced_no_applied_changes")
        except Exception as error:
            rollback_result = _rollback_and_check(result, record, root, source_snapshot, result_path, started, "behavior_repair_model_invalid")
            if rollback_result is not None:
                return rollback_result
            record["status"] = "failed"
            record["error"] = f"{type(error).__name__}: {error}"
            _write_json(repair_path, {"status": "failed", "error": record["error"]})
            return _gate(result, result_path, started, "behavior_repair_model_invalid")

        try:
            _refresh_project_evidence(root)
            build_result = _plain_mapping(rebuild_callback(root), "build result")
            _write_json(build_path, build_result)
            record["build_result"] = build_path.relative_to(root).as_posix()
            result["final_build_result"] = build_result
            result["artifacts"]["final_build"] = build_path.relative_to(root).as_posix()
        except Exception as error:
            rollback_result = _rollback_and_check(result, record, root, source_snapshot, result_path, started, "behavior_repair_build_unavailable")
            if rollback_result is not None:
                return rollback_result
            record["status"] = "failed"
            record["error"] = f"{type(error).__name__}: {error}"
            _write_json(build_path, {"status": "failed", "error": record["error"]})
            return _gate(result, result_path, started, "behavior_repair_build_unavailable")
        if not _strict_build_passed(build_result):
            rollback_result = _rollback_and_check(result, record, root, source_snapshot, result_path, started, "behavior_repair_build_failed")
            if rollback_result is not None:
                return rollback_result
            compiler_diagnostics = collect_build_diagnostics(
                root,
                build_result,
                MAX_DIAGNOSTIC_BYTES_PER_ITERATION,
            ).strip()
            record["status"] = "retrying" if iteration < bounded_iterations and compiler_diagnostics else "failed"
            record["error"] = compiler_diagnostics or "reconstructed source did not compile"
            result["iterations_completed"] = iteration
            if iteration < bounded_iterations and compiler_diagnostics:
                previous_repair_error = "Compiler diagnostics from the rejected source change:\n" + compiler_diagnostics
                continue
            result["status"] = "failed"
            result["blocking_reasons"].append("behavior_repair_build_failed")
            return _finish(result, result_path, started)

        try:
            next_behavior = _plain_mapping(revalidate_callback(root), "behavior result")
        except Exception as error:
            rollback_result = _rollback_and_check(result, record, root, source_snapshot, result_path, started, "behavior_revalidation_unavailable")
            if rollback_result is not None:
                return rollback_result
            record["status"] = "failed"
            record["error"] = f"{type(error).__name__}: {error}"
            return _gate(result, result_path, started, "behavior_revalidation_unavailable")
        _write_json(after_path, next_behavior)
        record["behavior_after"] = after_path.relative_to(root).as_posix()
        result["artifacts"]["final_behavior"] = after_path.relative_to(root).as_posix()
        result["iterations_completed"] = iteration
        result["final_behavior_result"] = next_behavior
        committed_count = int(record["attempted_applied_change_count"])
        record["committed_applied_change_count"] = committed_count
        result["applied_change_count"] += committed_count
        current_behavior = next_behavior
        if _strict_behavior_passed(current_behavior):
            record["status"] = "passed"
            result["status"] = "passed"
            result["passed"] = True
            break
        if not _repairable_mismatch(current_behavior):
            record["status"] = "failed"
            result["status"] = "failed"
            result["blocking_reasons"].append("behavior_revalidation_not_repairable")
            break
        if not is_strict_real_behavior_mismatch(current_behavior):
            record["status"] = "dependency-gated"
            result["status"] = "dependency-gated"
            result["blocking_reasons"].append("strict_real_behavior_mismatch_required")
            break
        record["status"] = "mismatch"
    else:
        result["status"] = "exhausted"
        result["blocking_reasons"].append("behavior_repair_iteration_budget_exhausted")

    return _finish(result, result_path, started)


def _behavior_diff(value: Mapping[str, Any], byte_limit: int) -> tuple[dict[str, Any], str]:
    comparisons = []
    for item in _mapping_sequence(value.get("comparisons"))[:32]:
        if item.get("matched") is not False:
            continue
        comparison = {
            "name": str(item.get("name") or "unknown"),
            "kind": str(item.get("kind") or "unknown"),
            "matched": False,
            "original": _summarize(item.get("original")),
            "reconstructed": _summarize(item.get("reconstructed")),
        }
        for role in ("original", "reconstructed"):
            observation = _observation_summary(value, role, comparison["name"])
            if observation is not None:
                comparison[f"{role}_observation"] = observation
        comparisons.append(comparison)
    payload = {
        "comparisons": comparisons,
        "diagnostics": [str(item)[:512] for item in list(value.get("diagnostics") or [])[:16]],
        "blocking_reasons": [str(item)[:256] for item in list(value.get("blocking_reasons") or [])[:16]],
        "target_hints": _reconstructed_target_hints(value),
    }
    candidates = [
        payload,
        {
            "comparisons": [
                {key: item[key] for key in ("name", "kind", "matched", "original", "reconstructed") if key in item}
                for item in comparisons[:8]
            ],
            "diagnostics": [str(item)[:128] for item in payload["diagnostics"][:4]],
            "blocking_reasons": payload["blocking_reasons"][:4],
            "target_hints": [str(item)[:128] for item in payload["target_hints"][:8]],
            "truncated": True,
        },
        {
            "comparisons": [
                {key: item[key] for key in ("name", "kind", "matched") if key in item}
                for item in comparisons[:8]
            ],
            "truncated": True,
        },
        {"comparisons": [{"name": str(comparisons[0].get("name") or "unknown")[:32], "matched": False}], "truncated": True}
        if comparisons
        else {"comparisons": [], "truncated": True},
    ]
    for candidate in candidates:
        text = json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(text.encode("utf-8")) <= byte_limit:
            return candidate, text
    return {"comparisons": []}, ""


def _reconstructed_target_hints(value: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []
    commands = value.get("commands")
    reconstructed = commands.get("reconstructed") if isinstance(commands, Mapping) else None
    if isinstance(reconstructed, Mapping):
        argv = reconstructed.get("argv")
        if isinstance(argv, Sequence) and not isinstance(argv, (str, bytes)):
            candidates.extend(str(item) for item in argv)
    identity = value.get("target_identity")
    reconstructed_identity = identity.get("reconstructed") if isinstance(identity, Mapping) else None
    if isinstance(reconstructed_identity, Mapping) and reconstructed_identity.get("path"):
        candidates.append(str(reconstructed_identity["path"]))
    hints: list[str] = []
    for candidate in candidates:
        normalized = candidate.replace("\\", "/")[:512]
        if "targets/" in normalized and normalized not in hints:
            hints.append(normalized)
        if len(hints) >= 32:
            break
    return hints


def _observation_summary(value: Mapping[str, Any], role: str, name: str) -> dict[str, Any] | None:
    runs = value.get("runs")
    run = runs.get(role) if isinstance(runs, Mapping) else None
    if not isinstance(run, Mapping):
        return None
    if name == "exit_code":
        return {"exit_code": run.get("exit_code")}
    stream = run.get(name)
    if name in {"stdout", "stderr"} and isinstance(stream, Mapping):
        return {
            "text": str(stream.get("text") or "")[:2048],
            "sha256": stream.get("sha256"),
            "total_bytes": _nonnegative_int(stream.get("total_bytes")),
            "truncated": stream.get("truncated") is True or len(str(stream.get("text") or "")) > 2048,
        }
    outputs = run.get("outputs")
    for output in _mapping_sequence(outputs):
        if str(output.get("name") or "") == name:
            return _summarize(output)
    return None


def _summarize(value: Any) -> Any:
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    if isinstance(value, str):
        return value if len(value) <= 256 else value[:256] + "[truncated]"
    if isinstance(value, Mapping):
        return {str(key): _summarize(child) for key, child in list(value.items())[:16]}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_summarize(child) for child in list(value)[:16]]
    return str(value)[:256]


def _refresh_project_evidence(root: Path) -> dict[str, Any]:
    from ..knowledge.reconstruction_graph import build_reconstruction_graph
    from .project_manifest import build_project_manifests

    graph = build_reconstruction_graph(root)
    graph_path = graph.write_artifact(root / "docs" / "reconstruction-graph.json")
    existing = _read_json(root / "docs" / "project-manifest.json")
    targets = []
    if isinstance(existing, Mapping):
        for item in _mapping_sequence(existing.get("targets")):
            targets.append({"id": item.get("id"), "kind": item.get("kind"), "composite_path": item.get("path")})
    if not targets:
        targets_root = root / "targets"
        if targets_root.is_dir():
            targets = [{"id": path.name, "composite_path": f"targets/{path.name}"} for path in sorted(targets_root.iterdir()) if path.is_dir()]
    manifests = build_project_manifests(root, targets)
    graph_payload = graph.to_dict()
    persisted_graph = _read_json(graph_path)
    if not isinstance(persisted_graph, Mapping) or persisted_graph.get("fingerprint") != graph_payload["fingerprint"]:
        raise RuntimeError("reconstruction graph artifact does not match restored source tree")
    artifact_paths = [
        graph_path,
        root / manifests["artifacts"]["project_manifest"],
        root / manifests["artifacts"]["dependency_lock"],
        root / manifests["artifacts"]["build_readiness"],
    ]
    if any(not path.is_file() for path in artifact_paths):
        raise RuntimeError("restored project evidence artifacts are incomplete")
    project_payload = _read_json(artifact_paths[1])
    readiness_payload = _read_json(artifact_paths[3])
    if not isinstance(project_payload, Mapping) or not isinstance(readiness_payload, Mapping):
        raise RuntimeError("restored project manifest or readiness artifact is invalid")
    source_evidence_count = 0
    for target in _mapping_sequence(project_payload.get("targets")):
        for source in _mapping_sequence(target.get("source_files")):
            path = root / str(source.get("path") or "")
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != source.get("sha256"):
                raise RuntimeError("restored project manifest source hash does not match source tree")
            source_evidence_count += 1
    return {
        "status": "passed",
        "error": None,
        "graph_fingerprint": graph_payload["fingerprint"],
        "graph_node_count": graph_payload["node_count"],
        "source_evidence_count": source_evidence_count,
        "artifacts": [path.relative_to(root).as_posix() for path in artifact_paths],
    }


def _repairable_mismatch(value: Mapping[str, Any]) -> bool:
    return (
        value.get("status") == "failed"
        and value.get("behavior_equivalent") is False
        and any(item.get("matched") is False for item in _mapping_sequence(value.get("comparisons")))
    )


def _strict_real_provenance(value: Mapping[str, Any]) -> bool:
    provenance = value.get("provenance")
    validator = provenance.get("validator") if isinstance(provenance, Mapping) else None
    return (
        isinstance(validator, Mapping)
        and validator.get("real_subprocess") is True
        and validator.get("runner_injected") is False
        and validator.get("shell") is False
    )


def is_strict_real_behavior_mismatch(value: Mapping[str, Any]) -> bool:
    return _repairable_mismatch(value) and _strict_real_provenance(value)


def _strict_behavior_passed(value: Mapping[str, Any]) -> bool:
    return (
        value.get("status") == "passed"
        and value.get("behavior_equivalent") is True
        and _strict_real_provenance(value)
    )


def _strict_build_passed(value: Mapping[str, Any]) -> bool:
    return value.get("status") == "passed" and value.get("build_passed") is True and value.get("isolated") is True


def _normalize_repair(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("repair callback must return a mapping")
    changes = value.get("applied_changes", value.get("changes", []))
    if not isinstance(changes, Sequence) or isinstance(changes, (str, bytes)):
        raise TypeError("applied_changes must be a sequence")
    usage = value.get("usage") if isinstance(value.get("usage"), Mapping) else {}
    calls = value.get("calls") if isinstance(value.get("calls"), Sequence) and not isinstance(value.get("calls"), (str, bytes)) else []
    return {
        "applied_changes": [_json_value(item) for item in changes],
        "calls": _json_value(calls),
        "call_count": len(calls),
        "status": str(value.get("status") or "executed"),
        "error_kind": str(value.get("error_kind") or ""),
        "error": str(value.get("error") or ""),
        "provider": _json_value(value.get("provider")),
        "model": _json_value(value.get("model")),
        "usage": _normalized_usage(usage),
    }


def _normalized_usage(value: Mapping[str, Any]) -> dict[str, int]:
    input_tokens = _nonnegative_int(value.get("input_tokens", value.get("prompt_tokens", 0)))
    output_tokens = _nonnegative_int(value.get("output_tokens", value.get("completion_tokens", 0)))
    total_tokens = max(
        _nonnegative_int(value.get("total_tokens", 0)),
        input_tokens + output_tokens,
    )
    return {"input_tokens": input_tokens, "output_tokens": output_tokens, "total_tokens": total_tokens}


def _merge_usage(total: dict[str, int], addition: Mapping[str, int]) -> None:
    for key in total:
        total[key] += int(addition.get(key, 0))


def _mapping_sequence(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _bounded(value: int, maximum: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    return min(maximum, max(0, value))


def _nonnegative_int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _plain_mapping(value: Mapping[str, Any], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping")
    return _json_value(dict(value))


def _json_value(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _snapshot_target_files(root: Path) -> dict[str, bytes]:
    targets = root / "targets"
    if not targets.is_dir():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in targets.rglob("*")
        if path.is_file()
    }


def _restore_target_files(root: Path, snapshot: Mapping[str, bytes]) -> None:
    targets = root / "targets"
    if targets.is_dir():
        for path in targets.rglob("*"):
            if path.is_file() and path.relative_to(root).as_posix() not in snapshot:
                path.unlink()
    for relative, content in snapshot.items():
        path = root / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def _restore_iteration_baseline(root: Path, snapshot: Mapping[str, bytes]) -> dict[str, Any]:
    try:
        _restore_target_files(root, snapshot)
        return _refresh_project_evidence(root)
    except Exception as error:
        return {
            "status": "failed",
            "error": f"{type(error).__name__}: {error}",
            "graph_fingerprint": None,
            "artifacts": [],
        }


def _rollback_and_check(
    result: dict[str, Any],
    record: dict[str, Any],
    root: Path,
    snapshot: Mapping[str, bytes],
    result_path: Path,
    started: float,
    original_reason: str,
) -> dict[str, Any] | None:
    evidence = _restore_iteration_baseline(root, snapshot)
    record["evidence_refresh"] = evidence
    if evidence["status"] == "passed":
        return None
    record["status"] = "dependency-gated"
    record["error"] = str(evidence.get("error") or "project evidence refresh failed")
    result["status"] = "dependency-gated"
    for reason in (original_reason, "behavior_repair_evidence_refresh_failed"):
        if reason not in result["blocking_reasons"]:
            result["blocking_reasons"].append(reason)
    return _finish(result, result_path, started)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _gate(result: dict[str, Any], path: Path, started: float, reason: str) -> dict[str, Any]:
    result["status"] = "dependency-gated"
    result["blocking_reasons"].append(reason)
    return _finish(result, path, started)


def _finish(result: dict[str, Any], path: Path, started: float) -> dict[str, Any]:
    result["finished_at"] = _utc_now()
    result["duration_ms"] = max(0, round((time.monotonic() - started) * 1000))
    _write_json(path, result)
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "BEHAVIOR_REPAIR_SCHEMA_VERSION",
    "DEFAULT_BEHAVIOR_REPAIR_PATH",
    "DEFAULT_MAX_ITERATIONS",
    "MAX_DIAGNOSTIC_BYTES",
    "MAX_ITERATIONS",
    "run_behavior_repair_loop",
    "is_strict_real_behavior_mismatch",
]
