from __future__ import annotations

from typing import Any, Dict, Optional


def default_strategy_store() -> Dict[str, Any]:
    return {"strategies": {}}


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _metric_sign(metric_name: str) -> int:
    lowered = metric_name.lower()
    negative_tokens = (
        "risk",
        "overhead",
        "cost",
        "latency",
        "warning",
        "error",
        "failure",
        "hook",
    )
    if any(token in lowered for token in negative_tokens):
        return -1
    return 1


def normalize_strategy_status(status: Any) -> str:
    """Collapse provider statuses into the counters used for recommendations."""

    normalized = "_".join(
        str(status or "unknown").strip().lower().replace("-", "_").split()
    )
    if normalized in {
        "ok",
        "success",
        "succeeded",
        "passed",
        "completed",
        "complete",
    }:
        return "ok"
    if normalized in {
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
    }:
        return "unavailable"
    return "failed"


def record_strategy_result(
    store: Dict[str, Any],
    key: str,
    status: str,
    metrics: Optional[Dict[str, Any]] = None,
    sample_id: Optional[str] = None,
    backend: Optional[str] = None,
) -> Dict[str, Any]:
    metrics = metrics or {}
    store.setdefault("strategies", {})
    bucket = store["strategies"].setdefault(
        key,
        {
            "runs": 0,
            "successes": 0,
            "failures": 0,
            "unavailable": 0,
            "samples": [],
            "backends": {},
        },
    )

    bucket["runs"] += 1
    normalized_status = normalize_strategy_status(status)

    if normalized_status == "ok":
        bucket["successes"] += 1
    elif normalized_status == "unavailable":
        bucket["unavailable"] += 1
    else:
        bucket["failures"] += 1

    if backend:
        bucket["backends"][backend] = bucket["backends"].get(backend, 0) + 1

    if sample_id:
        samples = [item for item in bucket.get("samples", []) if item != sample_id]
        samples.append(sample_id)
        bucket["samples"] = samples[-20:]

    for metric_name, metric_value in metrics.items():
        if not _is_number(metric_value):
            continue
        total_key = f"total_{metric_name}"
        avg_key = f"avg_{metric_name}"
        bucket[total_key] = float(bucket.get(total_key, 0.0)) + float(metric_value)
        bucket[avg_key] = bucket[total_key] / float(bucket["runs"])

    bucket["success_rate"] = (
        float(bucket["successes"]) / float(bucket["runs"])
        if bucket["runs"]
        else 0.0
    )
    return bucket


def _score_bucket(bucket: Dict[str, Any]) -> float:
    runs = float(bucket.get("runs", 0))
    success_rate = float(bucket.get("success_rate", 0.0))

    score = success_rate * 100.0
    score += min(runs, 10.0) * 1.5

    for key, value in bucket.items():
        if not key.startswith("avg_") or not _is_number(value):
            continue

        metric_name = key[4:]
        sign = _metric_sign(metric_name)
        lowered = metric_name.lower()

        if any(token in lowered for token in ("similarity", "match_rate", "confidence", "coverage")):
            score += sign * float(value) * 20.0
        elif any(token in lowered for token in ("events", "controls", "widgets", "text", "nodes")):
            score += sign * min(float(value), 100.0) / 5.0
        else:
            score += sign * min(float(value), 50.0) / 10.0

    return score


def recommend_strategy(store: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    strategies = (store or {}).get("strategies", {})
    best_key = None
    best_bucket = None
    best_score = None

    for key, bucket in strategies.items():
        score = _score_bucket(bucket)
        if best_score is None or score > best_score:
            best_key = key
            best_bucket = bucket
            best_score = score

    if best_key is None or best_bucket is None or best_score is None:
        return None

    result = {
        "key": best_key,
        "score": round(best_score, 4),
        "runs": best_bucket.get("runs", 0),
        "success_rate": best_bucket.get("success_rate", 0.0),
    }

    for key, value in best_bucket.items():
        if key.startswith("avg_"):
            result[key] = value

    return result
