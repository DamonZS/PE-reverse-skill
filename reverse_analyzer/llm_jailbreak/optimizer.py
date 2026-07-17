from __future__ import annotations

import copy
import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple, Union

from .models import CheckpointError


ATTACK_MODES: Tuple[str, ...] = (
    "pair",
    "tap",
    "crescendo",
    "evolution",
    "builtin",
)
SUPPORTED_ATTACK_MODES = ATTACK_MODES
SCHEMA_VERSION = 1
OPTIMIZER_SCHEMA_VERSION = SCHEMA_VERSION

_NUMBER_TOLERANCE = 1e-9
_MAX_COUNT = (1 << 63) - 1


def _mode(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("attack mode must be a string")
    normalized = value.strip().lower()
    if normalized not in ATTACK_MODES:
        raise ValueError(f"unsupported attack mode: {value!r}")
    return normalized


def _non_empty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _finite_float(
    value: Any,
    field_name: str,
    *,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a finite number")
    normalized = float(value)
    if not math.isfinite(normalized):
        raise ValueError(f"{field_name} must be finite")
    if minimum is not None and normalized < minimum:
        raise ValueError(f"{field_name} must be at least {minimum:g}")
    if maximum is not None and normalized > maximum:
        raise ValueError(f"{field_name} must be at most {maximum:g}")
    return normalized


def _non_negative_int(value: Any, field_name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_COUNT
    ):
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _json_mapping_copy(value: Any, field_name: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a mapping")
    try:
        cloned = copy.deepcopy(dict(value))
        json.dumps(cloned, allow_nan=False, sort_keys=True)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError(
            f"{field_name} must be JSON serializable and contain finite numbers: {exc}"
        ) from exc
    return cloned


def _reject_unknown(
    value: Mapping[str, Any],
    allowed: Tuple[str, ...],
    field_name: str,
) -> None:
    unknown = sorted(str(key) for key in set(value) - set(allowed))
    if unknown:
        raise ValueError(
            f"{field_name} contains unknown fields: {', '.join(unknown)}"
        )


def _same_number(actual: float, expected: float) -> bool:
    return math.isclose(
        actual,
        expected,
        rel_tol=_NUMBER_TOLERANCE,
        abs_tol=_NUMBER_TOLERANCE,
    )


@dataclass(frozen=True)
class OptimizationObservation:
    mode: str
    candidate_id: str = ""
    score: float = 0.0
    success: bool = False
    refused: bool = False
    latency_seconds: float = 0.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", _mode(self.mode))
        if not isinstance(self.candidate_id, str):
            raise ValueError("candidate_id must be a string")
        object.__setattr__(self, "candidate_id", self.candidate_id.strip())
        object.__setattr__(
            self,
            "score",
            _finite_float(self.score, "score", minimum=0.0, maximum=1.0),
        )
        if not isinstance(self.success, bool):
            raise ValueError("success must be a boolean")
        if not isinstance(self.refused, bool):
            raise ValueError("refused must be a boolean")
        object.__setattr__(
            self,
            "latency_seconds",
            _finite_float(
                self.latency_seconds,
                "latency_seconds",
                minimum=0.0,
            ),
        )

    @property
    def attack_mode(self) -> str:
        return self.mode

    @property
    def latency(self) -> float:
        return self.latency_seconds

    @property
    def latency_ms(self) -> float:
        return self.latency_seconds * 1000.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "candidate_id": self.candidate_id,
            "score": self.score,
            "success": self.success,
            "refused": self.refused,
            "latency_seconds": self.latency_seconds,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OptimizationObservation":
        if not isinstance(value, Mapping):
            raise ValueError("observation must be a mapping")
        allowed = (
            "mode",
            "attack_mode",
            "candidate_id",
            "score",
            "success",
            "refused",
            "refusal",
            "latency_seconds",
            "latency",
            "latency_ms",
        )
        _reject_unknown(value, allowed, "observation")

        mode_value = value.get("mode", value.get("attack_mode"))
        if "mode" in value and "attack_mode" in value:
            if _mode(value["mode"]) != _mode(value["attack_mode"]):
                raise ValueError("observation mode aliases disagree")

        refused = value.get("refused", value.get("refusal", False))
        if "refused" in value and "refusal" in value:
            if value["refused"] != value["refusal"]:
                raise ValueError("observation refusal aliases disagree")

        latency_fields = [
            name
            for name in ("latency_seconds", "latency", "latency_ms")
            if name in value
        ]
        if not latency_fields:
            latency = 0.0
        else:
            converted = []
            for name in latency_fields:
                item = _finite_float(value[name], name, minimum=0.0)
                converted.append(item / 1000.0 if name == "latency_ms" else item)
            latency = converted[0]
            if any(not _same_number(item, latency) for item in converted[1:]):
                raise ValueError("observation latency aliases disagree")

        return cls(
            mode=mode_value,
            candidate_id=value.get("candidate_id", ""),
            score=value.get("score", 0.0),
            success=value.get("success", False),
            refused=refused,
            latency_seconds=latency,
        )


@dataclass(frozen=True)
class OptimizationRecommendation:
    mode: str
    exploration: bool
    reason: str
    utility: float = 0.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", _mode(self.mode))
        if not isinstance(self.exploration, bool):
            raise ValueError("exploration must be a boolean")
        object.__setattr__(self, "reason", _non_empty_string(self.reason, "reason"))
        object.__setattr__(
            self,
            "utility",
            _finite_float(self.utility, "utility"),
        )

    @property
    def attack_mode(self) -> str:
        return self.mode

    @property
    def explore(self) -> bool:
        return self.exploration

    @property
    def is_exploration(self) -> bool:
        return self.exploration

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "exploration": self.exploration,
            "reason": self.reason,
            "utility": self.utility,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OptimizationRecommendation":
        if not isinstance(value, Mapping):
            raise ValueError("recommendation must be a mapping")
        allowed = (
            "mode",
            "attack_mode",
            "exploration",
            "explore",
            "is_exploration",
            "reason",
            "utility",
        )
        _reject_unknown(value, allowed, "recommendation")
        mode_value = value.get("mode", value.get("attack_mode"))
        if "mode" in value and "attack_mode" in value:
            if _mode(value["mode"]) != _mode(value["attack_mode"]):
                raise ValueError("recommendation mode aliases disagree")

        exploration_values = [
            value[name]
            for name in ("exploration", "explore", "is_exploration")
            if name in value
        ]
        if not exploration_values:
            raise ValueError("recommendation exploration is required")
        if any(item != exploration_values[0] for item in exploration_values[1:]):
            raise ValueError("recommendation exploration aliases disagree")
        return cls(
            mode=mode_value,
            exploration=exploration_values[0],
            reason=value.get("reason", "restored"),
            utility=value.get("utility", 0.0),
        )


@dataclass
class _ModeHistory:
    runs: int = 0
    successes: int = 0
    score_total: float = 0.0
    best_score: float = 0.0
    refusals: int = 0
    latency_total_seconds: float = 0.0
    consecutive_failures: int = 0
    recent_candidate_ids: list[str] = field(default_factory=list)

    def observe(self, observation: OptimizationObservation, recent_limit: int) -> None:
        if self.runs >= _MAX_COUNT:
            raise ValueError("mode runs exceed the supported checkpoint limit")
        score_total = self.score_total + observation.score
        latency_total = self.latency_total_seconds + observation.latency_seconds
        if not math.isfinite(score_total):
            raise ValueError("cumulative score must remain finite")
        if not math.isfinite(latency_total):
            raise ValueError("cumulative latency must remain finite")

        self.runs += 1
        self.successes += int(observation.success)
        self.score_total = score_total
        self.best_score = max(self.best_score, observation.score)
        self.refusals += int(observation.refused)
        self.latency_total_seconds = latency_total
        if observation.success:
            self.consecutive_failures = 0
        else:
            self.consecutive_failures += 1
        if observation.candidate_id:
            self.recent_candidate_ids.append(observation.candidate_id)
            del self.recent_candidate_ids[:-recent_limit]

    @property
    def average_score(self) -> float:
        return self.score_total / self.runs if self.runs else 0.0

    @property
    def success_rate(self) -> float:
        return self.successes / self.runs if self.runs else 0.0

    @property
    def refusal_rate(self) -> float:
        return self.refusals / self.runs if self.runs else 0.0

    @property
    def average_latency_seconds(self) -> float:
        return self.latency_total_seconds / self.runs if self.runs else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runs": self.runs,
            "success": self.successes,
            "successes": self.successes,
            "success_rate": self.success_rate,
            "score_total": self.score_total,
            "best_score": self.best_score,
            "avg_score": self.average_score,
            "average_score": self.average_score,
            "refusals": self.refusals,
            "refusal_rate": self.refusal_rate,
            "latency": self.average_latency_seconds,
            "latency_seconds": self.average_latency_seconds,
            "latency_total_seconds": self.latency_total_seconds,
            "total_latency_seconds": self.latency_total_seconds,
            "average_latency_seconds": self.average_latency_seconds,
            "consecutive_failures": self.consecutive_failures,
            "recent_candidate_ids": list(self.recent_candidate_ids),
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        mode: str,
        recent_limit: int,
    ) -> "_ModeHistory":
        if not isinstance(value, Mapping):
            raise ValueError(f"modes.{mode} must be a mapping")
        allowed = (
            "runs",
            "success",
            "successes",
            "success_rate",
            "score_total",
            "best_score",
            "avg_score",
            "average_score",
            "refusals",
            "refusal_rate",
            "latency",
            "latency_seconds",
            "latency_total_seconds",
            "total_latency_seconds",
            "average_latency_seconds",
            "consecutive_failures",
            "recent_candidate_ids",
        )
        _reject_unknown(value, allowed, f"modes.{mode}")
        prefix = f"modes.{mode}"

        runs = _non_negative_int(value.get("runs", 0), f"{prefix}.runs")
        success_values = [
            _non_negative_int(value[name], f"{prefix}.{name}")
            for name in ("success", "successes")
            if name in value
        ]
        successes = success_values[0] if success_values else 0
        if any(item != successes for item in success_values[1:]):
            raise ValueError(f"{prefix} success aliases disagree")
        if successes > runs:
            raise ValueError(f"{prefix}.successes cannot exceed runs")

        average_values = [
            _finite_float(
                value[name],
                f"{prefix}.{name}",
                minimum=0.0,
                maximum=1.0,
            )
            for name in ("avg_score", "average_score")
            if name in value
        ]
        score_total = (
            _finite_float(
                value["score_total"],
                f"{prefix}.score_total",
                minimum=0.0,
            )
            if "score_total" in value
            else (average_values[0] * runs if average_values else 0.0)
        )
        if score_total > runs + _NUMBER_TOLERANCE:
            raise ValueError(f"{prefix}.score_total cannot exceed runs")
        average_score = score_total / runs if runs else 0.0
        if any(not _same_number(item, average_score) for item in average_values):
            raise ValueError(f"{prefix} average score fields are inconsistent")

        best_score = _finite_float(
            value.get("best_score", 0.0),
            f"{prefix}.best_score",
            minimum=0.0,
            maximum=1.0,
        )
        if runs == 0 and (score_total or best_score):
            raise ValueError(f"{prefix} empty history contains score data")
        if runs and best_score + _NUMBER_TOLERANCE < average_score:
            raise ValueError(f"{prefix}.best_score cannot be below average_score")
        if best_score > score_total + _NUMBER_TOLERANCE:
            raise ValueError(f"{prefix}.best_score cannot exceed score_total")

        refusal_rate_value = None
        if "refusal_rate" in value:
            refusal_rate_value = _finite_float(
                value["refusal_rate"],
                f"{prefix}.refusal_rate",
                minimum=0.0,
                maximum=1.0,
            )
        if "refusals" in value:
            refusals = _non_negative_int(value["refusals"], f"{prefix}.refusals")
        elif refusal_rate_value is None:
            refusals = 0
        else:
            refusal_count = refusal_rate_value * runs
            refusals = int(round(refusal_count))
            if not _same_number(float(refusals), refusal_count):
                raise ValueError(f"{prefix}.refusal_rate does not represent a count")
        if refusals > runs:
            raise ValueError(f"{prefix}.refusals cannot exceed runs")
        refusal_rate = refusals / runs if runs else 0.0
        if refusal_rate_value is not None and not _same_number(
            refusal_rate_value, refusal_rate
        ):
            raise ValueError(f"{prefix}.refusal_rate is inconsistent")

        if "success_rate" in value:
            success_rate = _finite_float(
                value["success_rate"],
                f"{prefix}.success_rate",
                minimum=0.0,
                maximum=1.0,
            )
            expected_success_rate = successes / runs if runs else 0.0
            if not _same_number(success_rate, expected_success_rate):
                raise ValueError(f"{prefix}.success_rate is inconsistent")

        latency_average_values = [
            _finite_float(value[name], f"{prefix}.{name}", minimum=0.0)
            for name in ("latency", "latency_seconds", "average_latency_seconds")
            if name in value
        ]
        latency_total_values = [
            _finite_float(value[name], f"{prefix}.{name}", minimum=0.0)
            for name in ("latency_total_seconds", "total_latency_seconds")
            if name in value
        ]
        if latency_total_values:
            latency_total = latency_total_values[0]
            if any(
                not _same_number(item, latency_total)
                for item in latency_total_values[1:]
            ):
                raise ValueError(f"{prefix} latency total aliases disagree")
        elif latency_average_values:
            latency_total = latency_average_values[0] * runs
        else:
            latency_total = 0.0
        average_latency = latency_total / runs if runs else 0.0
        if any(
            not _same_number(item, average_latency)
            for item in latency_average_values
        ):
            raise ValueError(f"{prefix} average latency fields are inconsistent")
        if runs == 0 and latency_total:
            raise ValueError(f"{prefix} empty history contains latency data")

        consecutive_failures = _non_negative_int(
            value.get("consecutive_failures", 0),
            f"{prefix}.consecutive_failures",
        )
        if consecutive_failures > runs:
            raise ValueError(f"{prefix}.consecutive_failures cannot exceed runs")

        candidates = value.get("recent_candidate_ids", [])
        if not isinstance(candidates, (list, tuple)):
            raise ValueError(f"{prefix}.recent_candidate_ids must be an array")
        recent_candidate_ids = []
        for index, candidate_id in enumerate(candidates):
            if not isinstance(candidate_id, str) or not candidate_id.strip():
                raise ValueError(
                    f"{prefix}.recent_candidate_ids[{index}] must be a non-empty string"
                )
            recent_candidate_ids.append(candidate_id.strip())
        if runs == 0 and recent_candidate_ids:
            raise ValueError(f"{prefix} empty history contains candidate ids")
        recent_candidate_ids = recent_candidate_ids[-recent_limit:]

        return cls(
            runs=runs,
            successes=successes,
            score_total=score_total,
            best_score=best_score,
            refusals=refusals,
            latency_total_seconds=latency_total,
            consecutive_failures=consecutive_failures,
            recent_candidate_ids=recent_candidate_ids,
        )

    def merge(self, newer: "_ModeHistory", recent_limit: int) -> None:
        merged_runs = self.runs + newer.runs
        if merged_runs > _MAX_COUNT:
            raise ValueError("merged mode runs exceed the supported checkpoint limit")
        merged_score_total = self.score_total + newer.score_total
        merged_latency_total = (
            self.latency_total_seconds + newer.latency_total_seconds
        )
        if not math.isfinite(merged_score_total):
            raise ValueError("merged cumulative score must remain finite")
        if not math.isfinite(merged_latency_total):
            raise ValueError("merged cumulative latency must remain finite")

        previous_failures = self.consecutive_failures
        self.runs = merged_runs
        self.successes += newer.successes
        self.score_total = merged_score_total
        self.best_score = max(self.best_score, newer.best_score)
        self.refusals += newer.refusals
        self.latency_total_seconds = merged_latency_total
        if newer.runs:
            if newer.consecutive_failures == newer.runs:
                self.consecutive_failures = previous_failures + newer.runs
            else:
                self.consecutive_failures = newer.consecutive_failures
        self.recent_candidate_ids.extend(newer.recent_candidate_ids)
        del self.recent_candidate_ids[:-recent_limit]


ObservationInput = Union[OptimizationObservation, Mapping[str, Any], str]


class CheckpointOptimizer:
    """Persistent deterministic mode selector for adaptive attack campaigns."""

    schema_version = SCHEMA_VERSION
    modes = ATTACK_MODES

    def __init__(
        self,
        objective: str,
        model: str,
        campaign_fingerprint: str,
        *,
        recent_candidate_limit: int = 16,
        exploration_weight: float = 0.2,
    ) -> None:
        self.objective = _non_empty_string(objective, "objective")
        self.model = _non_empty_string(model, "model")
        self.campaign_fingerprint = _non_empty_string(
            campaign_fingerprint,
            "campaign_fingerprint",
        )
        if (
            isinstance(recent_candidate_limit, bool)
            or not isinstance(recent_candidate_limit, int)
            or not 1 <= recent_candidate_limit <= 10000
        ):
            raise ValueError("recent_candidate_limit must be between 1 and 10000")
        self.recent_candidate_limit = recent_candidate_limit
        self.exploration_weight = _finite_float(
            exploration_weight,
            "exploration_weight",
            minimum=0.0,
            maximum=10.0,
        )
        self._histories = {mode: _ModeHistory() for mode in ATTACK_MODES}
        self._algorithm_state: Dict[str, Dict[str, Any]] = {}

    @property
    def identity(self) -> Dict[str, str]:
        return {
            "objective": self.objective,
            "model": self.model,
            "campaign_fingerprint": self.campaign_fingerprint,
        }

    def observe(
        self,
        observation: Optional[ObservationInput] = None,
        **values: Any,
    ) -> OptimizationRecommendation:
        if isinstance(observation, OptimizationObservation):
            if values:
                raise TypeError(
                    "observation fields cannot accompany an OptimizationObservation"
                )
            normalized = observation
        elif isinstance(observation, Mapping):
            if values:
                raise TypeError("observation fields cannot accompany a mapping")
            normalized = OptimizationObservation.from_dict(observation)
        elif isinstance(observation, str):
            payload = dict(values)
            if "mode" in payload or "attack_mode" in payload:
                raise TypeError("mode was provided more than once")
            payload["mode"] = observation
            normalized = OptimizationObservation.from_dict(payload)
        elif observation is None:
            normalized = OptimizationObservation.from_dict(values)
        else:
            raise TypeError(
                "observation must be an OptimizationObservation, mapping, mode, or null"
            )

        self._histories[normalized.mode].observe(
            normalized,
            self.recent_candidate_limit,
        )
        return self.recommend()

    def recommend(
        self,
        allowed_modes: Optional[Sequence[str]] = None,
    ) -> OptimizationRecommendation:
        modes = self._allowed_modes(allowed_modes)
        for mode in modes:
            if self._histories[mode].runs == 0:
                return OptimizationRecommendation(
                    mode=mode,
                    exploration=True,
                    reason="cold_start",
                    utility=1.0,
                )

        total_runs = sum(self._histories[mode].runs for mode in modes)
        exploitation = {
            mode: self._exploitation_value(self._histories[mode])
            for mode in modes
        }
        utilities = {
            mode: exploitation[mode]
            + self.exploration_weight
            * math.sqrt(math.log(total_runs + 1.0) / self._histories[mode].runs)
            for mode in modes
        }
        selected = max(
            modes,
            key=lambda mode: (utilities[mode], -modes.index(mode)),
        )
        empirical_best = max(
            modes,
            key=lambda mode: (exploitation[mode], -modes.index(mode)),
        )
        exploring = selected != empirical_best
        return OptimizationRecommendation(
            mode=selected,
            exploration=exploring,
            reason="exploration_bonus" if exploring else "balanced_utility",
            utility=round(utilities[selected], 12),
        )

    @staticmethod
    def _allowed_modes(allowed_modes: Optional[Sequence[str]]) -> Tuple[str, ...]:
        if allowed_modes is None:
            return ATTACK_MODES
        if isinstance(allowed_modes, (str, bytes)):
            raise ValueError("allowed_modes must be a non-empty sequence")
        modes = tuple(_mode(item) for item in allowed_modes)
        if not modes:
            raise ValueError("allowed_modes must be a non-empty sequence")
        if len(set(modes)) != len(modes):
            raise ValueError("allowed_modes must not contain duplicates")
        return modes

    def recommend_next(
        self,
        allowed_modes: Optional[Sequence[str]] = None,
    ) -> OptimizationRecommendation:
        return self.recommend(allowed_modes)

    def recommend_next_mode(
        self,
        allowed_modes: Optional[Sequence[str]] = None,
    ) -> OptimizationRecommendation:
        return self.recommend(allowed_modes)

    @staticmethod
    def _exploitation_value(history: _ModeHistory) -> float:
        latency_quality = 1.0 / (1.0 + history.average_latency_seconds)
        failure_penalty = min(0.2, 0.025 * history.consecutive_failures)
        return (
            0.50 * history.average_score
            + 0.30 * history.success_rate
            + 0.15 * (1.0 - history.refusal_rate)
            + 0.05 * latency_quality
            - failure_penalty
        )

    def stats_for(self, mode: str) -> Dict[str, Any]:
        return copy.deepcopy(self._histories[_mode(mode)].to_dict())

    def statistics(self) -> Dict[str, Dict[str, Any]]:
        return {mode: self.stats_for(mode) for mode in ATTACK_MODES}

    def attach_state(self, mode: str, mapping: Mapping[str, Any]) -> None:
        normalized_mode = _mode(mode)
        self._algorithm_state[normalized_mode] = _json_mapping_copy(
            mapping,
            f"algorithm state for {normalized_mode}",
        )

    def state_for(self, mode: str) -> Dict[str, Any]:
        normalized_mode = _mode(mode)
        return copy.deepcopy(self._algorithm_state.get(normalized_mode, {}))

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "objective": self.objective,
            "model": self.model,
            "campaign_fingerprint": self.campaign_fingerprint,
            "recent_candidate_limit": self.recent_candidate_limit,
            "exploration_weight": self.exploration_weight,
            "modes": {
                mode: self._histories[mode].to_dict() for mode in ATTACK_MODES
            },
            "algorithm_state": copy.deepcopy(self._algorithm_state),
        }
        try:
            json.dumps(payload, allow_nan=False, sort_keys=True)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"optimizer state is not JSON serializable: {exc}") from exc
        return payload

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        objective: Optional[str] = None,
        model: Optional[str] = None,
        campaign_fingerprint: Optional[str] = None,
    ) -> "CheckpointOptimizer":
        try:
            return cls._from_dict(
                value,
                objective=objective,
                model=model,
                campaign_fingerprint=campaign_fingerprint,
            )
        except CheckpointError:
            raise
        except (TypeError, ValueError, KeyError, OverflowError) as exc:
            raise CheckpointError(f"invalid optimizer checkpoint: {exc}") from exc

    @classmethod
    def _from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        objective: Optional[str],
        model: Optional[str],
        campaign_fingerprint: Optional[str],
    ) -> "CheckpointOptimizer":
        if not isinstance(value, Mapping):
            raise ValueError("optimizer checkpoint must be a mapping")
        allowed = (
            "schema_version",
            "objective",
            "model",
            "campaign_fingerprint",
            "recent_candidate_limit",
            "exploration_weight",
            "modes",
            "algorithm_state",
        )
        _reject_unknown(value, allowed, "optimizer checkpoint")
        schema_version = value.get("schema_version")
        if (
            isinstance(schema_version, bool)
            or not isinstance(schema_version, int)
            or schema_version != SCHEMA_VERSION
        ):
            raise CheckpointError(
                "optimizer checkpoint schema_version mismatch: "
                f"expected {SCHEMA_VERSION}, got {schema_version!r}"
            )

        stored_identity = {
            "objective": _non_empty_string(value.get("objective"), "objective"),
            "model": _non_empty_string(value.get("model"), "model"),
            "campaign_fingerprint": _non_empty_string(
                value.get("campaign_fingerprint"),
                "campaign_fingerprint",
            ),
        }
        expected_identity = {
            "objective": objective,
            "model": model,
            "campaign_fingerprint": campaign_fingerprint,
        }
        for field_name, expected in expected_identity.items():
            if expected is None:
                continue
            normalized_expected = _non_empty_string(expected, field_name)
            if normalized_expected != stored_identity[field_name]:
                raise CheckpointError(
                    f"optimizer checkpoint {field_name} mismatch: "
                    f"expected {normalized_expected!r}, "
                    f"got {stored_identity[field_name]!r}"
                )

        recent_limit = value.get("recent_candidate_limit", 16)
        exploration_weight = value.get("exploration_weight", 0.2)
        optimizer = cls(
            **stored_identity,
            recent_candidate_limit=recent_limit,
            exploration_weight=exploration_weight,
        )

        raw_modes = value.get("modes")
        if not isinstance(raw_modes, Mapping):
            raise ValueError("modes must be a mapping")
        unknown_modes = sorted(str(item) for item in set(raw_modes) - set(ATTACK_MODES))
        missing_modes = [mode for mode in ATTACK_MODES if mode not in raw_modes]
        if unknown_modes:
            raise ValueError(f"modes contains unsupported values: {', '.join(unknown_modes)}")
        if missing_modes:
            raise ValueError(f"modes is missing values: {', '.join(missing_modes)}")
        optimizer._histories = {
            mode: _ModeHistory.from_dict(
                raw_modes[mode],
                mode=mode,
                recent_limit=optimizer.recent_candidate_limit,
            )
            for mode in ATTACK_MODES
        }

        raw_state = value.get("algorithm_state", {})
        if not isinstance(raw_state, Mapping):
            raise ValueError("algorithm_state must be a mapping")
        unknown_state_modes = sorted(
            str(item) for item in set(raw_state) - set(ATTACK_MODES)
        )
        if unknown_state_modes:
            raise ValueError(
                "algorithm_state contains unsupported modes: "
                + ", ".join(unknown_state_modes)
            )
        for mode, state in raw_state.items():
            optimizer.attach_state(mode, state)
        return optimizer

    def merge(
        self,
        other: Union["CheckpointOptimizer", Mapping[str, Any]],
    ) -> "CheckpointOptimizer":
        if isinstance(other, Mapping):
            other = self.from_dict(other, **self.identity)
        if not isinstance(other, CheckpointOptimizer):
            raise TypeError("other must be a CheckpointOptimizer or checkpoint mapping")
        if other is self:
            return self
        self._assert_same_identity(other)
        merged_histories = copy.deepcopy(self._histories)
        for mode in ATTACK_MODES:
            merged_histories[mode].merge(
                other._histories[mode],
                self.recent_candidate_limit,
            )
        self._histories = merged_histories
        for mode, state in other._algorithm_state.items():
            self._algorithm_state[mode] = copy.deepcopy(state)
        return self

    def _assert_same_identity(self, other: "CheckpointOptimizer") -> None:
        for field_name in ("objective", "model", "campaign_fingerprint"):
            current = getattr(self, field_name)
            incoming = getattr(other, field_name)
            if current != incoming:
                raise CheckpointError(
                    f"optimizer {field_name} mismatch: "
                    f"expected {current!r}, got {incoming!r}"
                )


__all__ = [
    "ATTACK_MODES",
    "CheckpointOptimizer",
    "OPTIMIZER_SCHEMA_VERSION",
    "OptimizationObservation",
    "OptimizationRecommendation",
    "SCHEMA_VERSION",
    "SUPPORTED_ATTACK_MODES",
]
