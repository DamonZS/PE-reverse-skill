"""Privacy-preserving capability outcome knowledge.

The store deliberately keeps only aggregate lifecycle metrics and a bounded
set of hashed target identities. Provider snapshots, target paths, PIDs,
display names, artifact paths, and rollback details never enter the schema.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Dict, Iterator, Optional, Tuple

from reverse_analyzer.core.models import utc_now


CAPABILITY_OUTCOME_SCHEMA_VERSION = 1
CAPABILITY_SAMPLE_LIMIT = 20
_IDENTITY_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")

_SUCCESS_STATUSES = {
    "ok",
    "success",
    "succeeded",
    "passed",
    "completed",
    "complete",
}
_UNAVAILABLE_STATUSES = {
    "unavailable",
    "unsupported",
    "skipped",
    "not_run",
    "not_attempted",
    "not_executed",
    "mock",
    "mocked",
    "dry_run",
    "dryrun",
    "simulated",
    "simulation",
    "planned",
    "preview",
    "stubbed",
}


def _mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            payload = to_dict()
        except (TypeError, ValueError):
            return {}
        if isinstance(payload, Mapping):
            return dict(payload)
    return {}


def _name(value: Any, *, default: str = "unknown") -> str:
    normalized = "_".join(str(value or "").strip().lower().split())
    return normalized or default


def _status(value: Any) -> str:
    return _name(value, default="unknown").replace("-", "_")


def _status_category(value: Any) -> str:
    normalized = _status(value)
    if normalized in _SUCCESS_STATUSES:
        return "successes"
    if normalized in _UNAVAILABLE_STATUSES:
        return "unavailable"
    return "failures"


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _finite_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return float(value)
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if math.isfinite(number) else default


def _duration(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    return max(0.0, _finite_float(value))


def _completeness(value: Any, *, default: float = 0.0) -> float:
    if value is None:
        return default
    return min(1.0, max(0.0, _finite_float(value, default)))


def _metric_name(value: Any) -> str:
    return _name(value, default="").replace("-", "_")


def _normalize_quality_metrics(value: Any) -> Dict[str, float]:
    metrics: Dict[str, float] = {}
    for raw_name, raw_value in _mapping(value).items():
        name = _metric_name(raw_name)
        nested = _mapping(raw_value)
        if nested:
            raw_value = nested.get(
                "average",
                nested.get("avg", nested.get("value")),
            )
        number = _finite_float(raw_value, -1.0)
        if name and number >= 0.0:
            if 1.0 < number <= 100.0:
                number /= 100.0
            metrics[name] = round(_completeness(number), 6)
    return dict(sorted(metrics.items()))


def _quality_totals(value: Any) -> Dict[str, float]:
    totals: Dict[str, float] = {}
    for raw_name, raw_value in _mapping(value).items():
        name = _metric_name(raw_name)
        number = _finite_float(raw_value, -1.0)
        if name and number >= 0.0:
            totals[name] = number
    return totals


def _quality_counts(value: Any) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for raw_name, raw_value in _mapping(value).items():
        name = _metric_name(raw_name)
        count = max(0, _int(raw_value))
        if name and count:
            counts[name] = count
    return counts


def sanitize_capability_target(target: Any) -> Dict[str, str]:
    """Return only target kind and a deterministic, domain-separated hash."""

    payload = _mapping(target)
    kind = _name(payload.get("kind"), default="unknown")
    supplied_hash = str(payload.get("identity_hash") or "").strip()
    if _IDENTITY_HASH_RE.fullmatch(supplied_hash):
        identity_hash = supplied_hash.lower()
    else:
        identity_material = {
            key: payload.get(key)
            for key in ("sha256", "pid", "path", "display_name", "metadata")
            if payload.get(key) not in (None, "", {}, [])
        }
        canonical = json.dumps(
            {"kind": kind, "identity": identity_material},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        identity_hash = hashlib.sha256(
            b"reverse-analyzer:capability-target:v1\x00" + canonical.encode("utf-8")
        ).hexdigest()
    return {"kind": kind, "identity_hash": identity_hash}


def default_capability_outcome_store() -> Dict[str, Any]:
    return {
        "version": CAPABILITY_OUTCOME_SCHEMA_VERSION,
        "capabilities": {},
    }


def _normalize_sample(value: Any, *, target_kind: str) -> Optional[Dict[str, Any]]:
    payload = _mapping(value)
    if not payload:
        return None
    target = _mapping(payload.get("target"))
    target.setdefault("kind", target_kind)
    sample = {
        "recorded_at": str(payload.get("recorded_at") or payload.get("timestamp") or utc_now()),
        "status": _status(payload.get("status")),
        "target": sanitize_capability_target(target),
        "duration_ms": round(_duration(payload.get("duration_ms")), 6),
        "artifact_completeness": round(
            _completeness(payload.get("artifact_completeness")),
            6,
        ),
        "rollback_completeness": round(
            _completeness(payload.get("rollback_completeness")),
            6,
        ),
        "audit_completeness": round(
            _completeness(payload.get("audit_completeness")),
            6,
        ),
        "quality_metrics": _normalize_quality_metrics(
            payload.get("quality_metrics", payload.get("metrics"))
        ),
    }
    return sample


def _normalize_bucket(
    value: Any,
    *,
    capability: str,
    provider: str,
    action: str,
    target_kind: str,
) -> Dict[str, Any]:
    source = _mapping(value)
    runs = max(0, _int(source.get("runs")))
    successes = max(0, _int(source.get("successes", source.get("success"))))
    failures = max(0, _int(source.get("failures", source.get("failure"))))
    unavailable = max(0, _int(source.get("unavailable")))
    runs = max(runs, successes + failures + unavailable)

    status_counts = {
        _status(name): max(0, _int(count))
        for name, count in _mapping(source.get("status_counts")).items()
        if max(0, _int(count))
    }
    total_duration = _duration(source.get("total_duration_ms"))
    if total_duration == 0.0 and runs:
        total_duration = _duration(source.get("avg_duration_ms")) * runs
    total_artifacts = _finite_float(source.get("total_artifact_completeness"), -1.0)
    if total_artifacts < 0.0:
        total_artifacts = _completeness(
            source.get("artifact_completeness", source.get("artifact_completeness_rate"))
        ) * runs
    total_rollbacks = _finite_float(source.get("total_rollback_completeness"), -1.0)
    if total_rollbacks < 0.0:
        total_rollbacks = _completeness(
            source.get("rollback_completeness", source.get("rollback_completeness_rate"))
        ) * runs
    total_audit = _finite_float(source.get("total_audit_completeness"), -1.0)
    if total_audit < 0.0:
        total_audit = _completeness(
            source.get("audit_completeness", source.get("audit_completeness_rate"))
        ) * runs
    total_artifacts = min(float(runs), max(0.0, total_artifacts))
    total_rollbacks = min(float(runs), max(0.0, total_rollbacks))
    total_audit = min(float(runs), max(0.0, total_audit))

    average_quality = _normalize_quality_metrics(
        source.get("quality_metrics", source.get("avg_quality_metrics"))
    )
    quality_totals = _quality_totals(source.get("total_quality_metrics"))
    quality_counts = _quality_counts(source.get("quality_metric_counts"))
    for name in set(average_quality) | set(quality_totals) | set(quality_counts):
        count = quality_counts.get(name, 0)
        if runs:
            count = min(runs, count or runs)
        else:
            count = 0
        total = quality_totals.get(name)
        if total is None:
            total = average_quality.get(name, 0.0) * count
        quality_counts[name] = count
        quality_totals[name] = round(min(float(count), max(0.0, total)), 6)
    quality_counts = {
        name: count for name, count in sorted(quality_counts.items()) if count
    }
    quality_totals = {
        name: quality_totals[name] for name in quality_counts
    }

    samples = []
    raw_samples = source.get("samples")
    if not isinstance(raw_samples, list):
        raw_samples = source.get("recent_samples")
    if isinstance(raw_samples, list):
        for item in raw_samples[-CAPABILITY_SAMPLE_LIMIT:]:
            sample = _normalize_sample(item, target_kind=target_kind)
            if sample is not None:
                samples.append(sample)

    bucket = {
        "capability": capability,
        "provider": provider,
        "action": action,
        "target_kind": target_kind,
        "runs": runs,
        "successes": min(runs, successes),
        "failures": min(runs, failures),
        "unavailable": min(runs, unavailable),
        "status_counts": status_counts,
        "total_duration_ms": round(max(0.0, total_duration), 6),
        "total_artifact_completeness": round(total_artifacts, 6),
        "total_rollback_completeness": round(total_rollbacks, 6),
        "total_audit_completeness": round(total_audit, 6),
        "total_quality_metrics": quality_totals,
        "quality_metric_counts": quality_counts,
        "artifact_complete_runs": min(
            runs,
            max(0, _int(source.get("artifact_complete_runs"))),
        ),
        "rollback_complete_runs": min(
            runs,
            max(0, _int(source.get("rollback_complete_runs"))),
        ),
        "audit_complete_runs": min(
            runs,
            max(0, _int(source.get("audit_complete_runs"))),
        ),
        "samples": samples,
        "recent_samples": samples,
        "last_status": _status(
            source.get("last_status")
            or (samples[-1].get("status") if samples else None)
        ),
        "last_updated": str(source.get("last_updated") or ""),
    }
    _refresh_rates(bucket)
    return bucket


def _refresh_rates(bucket: Dict[str, Any]) -> None:
    runs = max(0, _int(bucket.get("runs")))
    if not runs:
        bucket["success_rate"] = 0.0
        bucket["failure_rate"] = 0.0
        bucket["unavailable_rate"] = 0.0
        bucket["availability_rate"] = 0.0
        bucket["avg_duration_ms"] = 0.0
        bucket["artifact_completeness"] = 0.0
        bucket["rollback_completeness"] = 0.0
        bucket["audit_completeness"] = 0.0
    else:
        bucket["success_rate"] = round(_int(bucket.get("successes")) / runs, 6)
        bucket["failure_rate"] = round(_int(bucket.get("failures")) / runs, 6)
        bucket["unavailable_rate"] = round(_int(bucket.get("unavailable")) / runs, 6)
        bucket["availability_rate"] = round(
            max(0.0, 1.0 - bucket["unavailable_rate"]),
            6,
        )
        bucket["avg_duration_ms"] = round(
            _duration(bucket.get("total_duration_ms")) / runs,
            6,
        )
        bucket["artifact_completeness"] = round(
            _completeness(
                _finite_float(bucket.get("total_artifact_completeness")) / runs
            ),
            6,
        )
        bucket["rollback_completeness"] = round(
            _completeness(
                _finite_float(bucket.get("total_rollback_completeness")) / runs
            ),
            6,
        )
        bucket["audit_completeness"] = round(
            _completeness(
                _finite_float(bucket.get("total_audit_completeness")) / runs
            ),
            6,
        )

    quality_totals = _quality_totals(bucket.get("total_quality_metrics"))
    quality_counts = _quality_counts(bucket.get("quality_metric_counts"))
    averages: Dict[str, float] = {}
    for name, count in sorted(quality_counts.items()):
        if count:
            averages[name] = round(
                _completeness(quality_totals.get(name, 0.0) / count),
                6,
            )
    bucket["total_quality_metrics"] = {
        name: round(min(float(quality_counts[name]), quality_totals.get(name, 0.0)), 6)
        for name in averages
    }
    bucket["quality_metric_counts"] = {
        name: quality_counts[name] for name in averages
    }
    bucket["quality_metrics"] = averages
    bucket["avg_quality_metrics"] = dict(averages)
    total_quality_count = sum(quality_counts.get(name, 0) for name in averages)
    bucket["quality_score"] = round(
        sum(bucket["total_quality_metrics"].values()) / total_quality_count,
        6,
    ) if total_quality_count else 0.0

    bucket["success"] = _int(bucket.get("successes"))
    bucket["failure"] = _int(bucket.get("failures"))
    bucket["artifact_completeness_rate"] = bucket["artifact_completeness"]
    bucket["rollback_completeness_rate"] = bucket["rollback_completeness"]
    bucket["audit_completeness_rate"] = bucket["audit_completeness"]
    samples = list(bucket.get("samples") or [])[-CAPABILITY_SAMPLE_LIMIT:]
    bucket["samples"] = samples
    bucket["recent_samples"] = samples


def _normalize_store(value: Any) -> Dict[str, Any]:
    payload = _mapping(value)
    store = default_capability_outcome_store()
    raw_capabilities = payload.get("capabilities")
    if isinstance(raw_capabilities, Mapping):
        for raw_capability, raw_capability_node in raw_capabilities.items():
            capability = _name(raw_capability)
            capability_node = _mapping(raw_capability_node)
            raw_providers = capability_node.get("providers")
            if not isinstance(raw_providers, Mapping):
                continue
            providers: Dict[str, Any] = {}
            for raw_provider, raw_provider_node in raw_providers.items():
                provider = _name(raw_provider)
                provider_node = _mapping(raw_provider_node)
                raw_actions = provider_node.get("actions")
                if not isinstance(raw_actions, Mapping):
                    continue
                actions: Dict[str, Any] = {}
                for raw_action, raw_action_node in raw_actions.items():
                    action = _name(raw_action)
                    action_node = _mapping(raw_action_node)
                    raw_target_kinds = action_node.get("target_kinds")
                    if not isinstance(raw_target_kinds, Mapping):
                        if any(
                            field_name in action_node
                            for field_name in (
                                "runs",
                                "success",
                                "successes",
                                "failure",
                                "failures",
                                "unavailable",
                                "samples",
                                "recent_samples",
                            )
                        ):
                            inferred_kind = _name(
                                action_node.get("target_kind"),
                                default="unknown",
                            )
                            raw_target_kinds = {inferred_kind: action_node}
                        else:
                            continue
                    target_kinds: Dict[str, Any] = {}
                    for raw_target_kind, raw_bucket in raw_target_kinds.items():
                        target_kind = _name(raw_target_kind)
                        target_kinds[target_kind] = _normalize_bucket(
                            raw_bucket,
                            capability=capability,
                            provider=provider,
                            action=action,
                            target_kind=target_kind,
                        )
                    if target_kinds:
                        actions[action] = {"target_kinds": target_kinds}
                if actions:
                    providers[provider] = {"actions": actions}
            if providers:
                store["capabilities"][capability] = {"providers": providers}
    if payload.get("last_updated") not in (None, ""):
        store["last_updated"] = str(payload["last_updated"])
    return store


def _ensure_bucket(
    store: Dict[str, Any],
    *,
    capability: str,
    provider: str,
    action: str,
    target_kind: str,
) -> Dict[str, Any]:
    capability_node = store["capabilities"].setdefault(capability, {"providers": {}})
    providers = capability_node.setdefault("providers", {})
    provider_node = providers.setdefault(provider, {"actions": {}})
    actions = provider_node.setdefault("actions", {})
    action_node = actions.setdefault(action, {"target_kinds": {}})
    target_kinds = action_node.setdefault("target_kinds", {})
    bucket = _normalize_bucket(
        target_kinds.get(target_kind),
        capability=capability,
        provider=provider,
        action=action,
        target_kind=target_kind,
    )
    target_kinds[target_kind] = bucket
    return bucket


def _iter_buckets(store: Dict[str, Any]) -> Iterator[Tuple[str, str, str, str, Dict[str, Any]]]:
    for capability, capability_node in store.get("capabilities", {}).items():
        for provider, provider_node in capability_node.get("providers", {}).items():
            for action, action_node in provider_node.get("actions", {}).items():
                for target_kind, bucket in action_node.get("target_kinds", {}).items():
                    if isinstance(bucket, dict):
                        yield capability, provider, action, target_kind, bucket


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return _normalize_store(json.load(handle))
    except (FileNotFoundError, json.JSONDecodeError, UnicodeError):
        return default_capability_outcome_store()


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary_path = Path(temporary_name)
    descriptor_open = True
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor_open = False
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if descriptor_open:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


class CapabilityOutcomeKnowledgeMixin:
    """KnowledgeBase APIs for recording and recommending capability providers."""

    root: Path

    @property
    def capability_outcomes_path(self) -> Path:
        return Path(self.root) / "capability_outcomes.json"

    def load_capability_outcomes(self) -> Dict[str, Any]:
        return _read_json(self.capability_outcomes_path)

    def save_capability_outcomes(self, data: Dict[str, Any]) -> None:
        _atomic_write_json(self.capability_outcomes_path, _normalize_store(data))

    def record_capability_outcome(
        self,
        capability: str,
        provider: str,
        action: str,
        *,
        status: str = "unknown",
        target: Any = None,
        target_identity: Any = None,
        duration_ms: Any = 0.0,
        artifact_completeness: Any = None,
        rollback_completeness: Any = None,
        audit_completeness: Any = None,
        quality_metrics: Any = None,
        artifact_complete: Optional[bool] = None,
        rollback_complete: Optional[bool] = None,
        audit_complete: Optional[bool] = None,
    ) -> Dict[str, Any]:
        capability_name = _name(capability, default="")
        provider_name = _name(provider, default="")
        action_name = _name(action, default="")
        if not capability_name:
            raise ValueError("Capability name must not be empty")
        if not provider_name:
            raise ValueError("Capability provider must not be empty")
        if not action_name:
            raise ValueError("Capability action must not be empty")

        sanitized_target = sanitize_capability_target(
            target if target is not None else target_identity
        )
        duration_value = _duration(duration_ms)
        if artifact_completeness is None and artifact_complete is not None:
            artifact_completeness = artifact_complete
        if rollback_completeness is None and rollback_complete is not None:
            rollback_completeness = rollback_complete
        if audit_completeness is None and audit_complete is not None:
            audit_completeness = audit_complete
        artifact_value = _completeness(artifact_completeness)
        rollback_value = _completeness(rollback_completeness)
        audit_value = _completeness(audit_completeness)
        quality_values = _normalize_quality_metrics(quality_metrics)
        status_name = _status(status)

        store = self.load_capability_outcomes()
        bucket = _ensure_bucket(
            store,
            capability=capability_name,
            provider=provider_name,
            action=action_name,
            target_kind=sanitized_target["kind"],
        )
        bucket["runs"] += 1
        category = _status_category(status_name)
        bucket[category] += 1
        bucket["status_counts"][status_name] = bucket["status_counts"].get(status_name, 0) + 1
        bucket["total_duration_ms"] = round(
            _duration(bucket.get("total_duration_ms")) + duration_value,
            6,
        )
        bucket["total_artifact_completeness"] = round(
            _finite_float(bucket.get("total_artifact_completeness")) + artifact_value,
            6,
        )
        bucket["total_rollback_completeness"] = round(
            _finite_float(bucket.get("total_rollback_completeness")) + rollback_value,
            6,
        )
        bucket["total_audit_completeness"] = round(
            _finite_float(bucket.get("total_audit_completeness")) + audit_value,
            6,
        )
        total_quality = _quality_totals(bucket.get("total_quality_metrics"))
        quality_counts = _quality_counts(bucket.get("quality_metric_counts"))
        for name, value in quality_values.items():
            total_quality[name] = round(total_quality.get(name, 0.0) + value, 6)
            quality_counts[name] = quality_counts.get(name, 0) + 1
        bucket["total_quality_metrics"] = total_quality
        bucket["quality_metric_counts"] = quality_counts
        if artifact_value >= 1.0:
            bucket["artifact_complete_runs"] += 1
        if rollback_value >= 1.0:
            bucket["rollback_complete_runs"] += 1
        if audit_value >= 1.0:
            bucket["audit_complete_runs"] += 1

        timestamp = utc_now()
        bucket["samples"].append(
            {
                "recorded_at": timestamp,
                "status": status_name,
                "target": sanitized_target,
                "duration_ms": round(duration_value, 6),
                "artifact_completeness": round(artifact_value, 6),
                "rollback_completeness": round(rollback_value, 6),
                "audit_completeness": round(audit_value, 6),
                "quality_metrics": quality_values,
            }
        )
        bucket["samples"] = bucket["samples"][-CAPABILITY_SAMPLE_LIMIT:]
        bucket["recent_samples"] = bucket["samples"]
        bucket["last_status"] = status_name
        bucket["last_updated"] = timestamp
        _refresh_rates(bucket)
        store["last_updated"] = timestamp
        self.save_capability_outcomes(store)
        return dict(bucket)

    def rank_capability_providers(
        self,
        capability: str,
        *,
        action: Optional[str] = None,
        target_kind: Optional[str] = None,
    ) -> list[Dict[str, Any]]:
        """Rank provider/action candidates using deterministic aggregate evidence."""

        requested_capability = _name(capability, default="")
        if not requested_capability:
            raise ValueError("Capability name must not be empty")
        requested_action = _name(action, default="") if action is not None else ""
        requested_target_kind = (
            _name(target_kind, default="") if target_kind is not None else ""
        )
        groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for candidate_capability, provider, candidate_action, candidate_kind, bucket in _iter_buckets(
            self.load_capability_outcomes()
        ):
            if candidate_capability != requested_capability:
                continue
            if requested_action and candidate_action != requested_action:
                continue
            if requested_target_kind and candidate_kind != requested_target_kind:
                continue
            group = groups.setdefault(
                (provider, candidate_action),
                {
                    "capability": candidate_capability,
                    "provider": provider,
                    "action": candidate_action,
                    "target_kinds": set(),
                    "runs": 0,
                    "successes": 0,
                    "failures": 0,
                    "unavailable": 0,
                    "total_duration_ms": 0.0,
                    "total_artifact_completeness": 0.0,
                    "total_rollback_completeness": 0.0,
                    "total_audit_completeness": 0.0,
                    "total_quality_metrics": {},
                    "quality_metric_counts": {},
                },
            )
            group["target_kinds"].add(candidate_kind)
            for counter in ("runs", "successes", "failures", "unavailable"):
                group[counter] += max(0, _int(bucket.get(counter)))
            for total_name in (
                "total_duration_ms",
                "total_artifact_completeness",
                "total_rollback_completeness",
                "total_audit_completeness",
            ):
                group[total_name] += max(0.0, _finite_float(bucket.get(total_name)))
            group_quality_totals = group["total_quality_metrics"]
            for name, value in _quality_totals(bucket.get("total_quality_metrics")).items():
                group_quality_totals[name] = group_quality_totals.get(name, 0.0) + value
            group_quality_counts = group["quality_metric_counts"]
            for name, count in _quality_counts(bucket.get("quality_metric_counts")).items():
                group_quality_counts[name] = group_quality_counts.get(name, 0) + count

        candidates: list[Dict[str, Any]] = []
        for group in groups.values():
            runs = max(0, _int(group.get("runs")))
            if not runs:
                continue
            successes = min(runs, max(0, _int(group.get("successes"))))
            failures = min(runs, max(0, _int(group.get("failures"))))
            unavailable = min(runs, max(0, _int(group.get("unavailable"))))
            success_rate = successes / runs
            failure_rate = failures / runs
            unavailable_rate = unavailable / runs
            availability_rate = max(0.0, 1.0 - unavailable_rate)
            artifact_rate = _completeness(
                _finite_float(group.get("total_artifact_completeness")) / runs
            )
            rollback_rate = _completeness(
                _finite_float(group.get("total_rollback_completeness")) / runs
            )
            audit_rate = _completeness(
                _finite_float(group.get("total_audit_completeness")) / runs
            )
            quality_totals = _quality_totals(group.get("total_quality_metrics"))
            quality_counts = _quality_counts(group.get("quality_metric_counts"))
            quality_averages = {
                name: round(
                    _completeness(quality_totals.get(name, 0.0) / count),
                    6,
                )
                for name, count in sorted(quality_counts.items())
                if count
            }
            quality_count = sum(quality_counts.get(name, 0) for name in quality_averages)
            quality_score = (
                sum(quality_totals.get(name, 0.0) for name in quality_averages)
                / quality_count
                if quality_count
                else 0.0
            )

            bayesian_success = (successes + 1.0) / (runs + 2.0)
            raw_score = (
                bayesian_success * 60.0
                + availability_rate * 8.0
                + max(0.0, 1.0 - failure_rate) * 7.0
                + artifact_rate * 8.0
                + rollback_rate * 5.0
                + audit_rate * 7.0
                + quality_score * 5.0
            )
            evidence_weight = runs / (runs + 4.0)
            score = 50.0 + (raw_score - 50.0) * evidence_weight
            target_kinds = sorted(group["target_kinds"])
            candidates.append(
                {
                    "capability": group["capability"],
                    "provider": group["provider"],
                    "action": group["action"],
                    "target_kind": target_kinds[0] if len(target_kinds) == 1 else None,
                    "target_kinds": target_kinds,
                    "score": round(min(100.0, max(0.0, score)), 6),
                    "runs": runs,
                    "successes": successes,
                    "failures": failures,
                    "unavailable": unavailable,
                    "success_rate": round(success_rate, 6),
                    "failure_rate": round(failure_rate, 6),
                    "unavailable_rate": round(unavailable_rate, 6),
                    "availability_rate": round(availability_rate, 6),
                    "avg_duration_ms": round(
                        _duration(group.get("total_duration_ms")) / runs,
                        6,
                    ),
                    "artifact_completeness": artifact_rate,
                    "rollback_completeness": rollback_rate,
                    "audit_completeness": audit_rate,
                    "quality_metrics": quality_averages,
                    "quality_score": round(_completeness(quality_score), 6),
                    "evidence_weight": round(evidence_weight, 6),
                }
            )
        candidates.sort(
            key=lambda item: (
                -_finite_float(item.get("score")),
                -_finite_float(item.get("success_rate")),
                -_int(item.get("runs")),
                str(item.get("provider") or ""),
                str(item.get("action") or ""),
                str(item.get("target_kind") or ""),
            )
        )
        return candidates

    def recommend_capability_provider(
        self,
        capability: str,
        *,
        action: Optional[str] = None,
        target_kind: Optional[str] = None,
        default_provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        requested_capability = _name(capability, default="")
        if not requested_capability:
            raise ValueError("Capability name must not be empty")
        requested_action = _name(action, default="") if action is not None else ""
        requested_target_kind = (
            _name(target_kind, default="") if target_kind is not None else ""
        )
        candidates = self.rank_capability_providers(
            requested_capability,
            action=requested_action or None,
            target_kind=requested_target_kind or None,
        )
        if candidates:
            return candidates[0]
        return {
            "capability": requested_capability,
            "provider": _name(default_provider, default="") if default_provider else None,
            "action": requested_action or None,
            "target_kind": requested_target_kind or None,
            "score": 0.0,
            "reason": "no capability outcome history",
        }

    def record_capability_result(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return self.record_capability_outcome(*args, **kwargs)

    def recommend_capability(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return self.recommend_capability_provider(*args, **kwargs)


__all__ = [
    "CAPABILITY_OUTCOME_SCHEMA_VERSION",
    "CAPABILITY_SAMPLE_LIMIT",
    "CapabilityOutcomeKnowledgeMixin",
    "default_capability_outcome_store",
    "sanitize_capability_target",
]
