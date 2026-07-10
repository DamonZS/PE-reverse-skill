"""Knowledge-base persistence for reverse-analysis evolution data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from reverse_analyzer.core.models import utc_now


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class KnowledgeBase:
    """Read/write helper for evolution JSON databases.

    Files managed under ``root``:
    - ``knowledge_base.json``: sample records and observations.
    - ``detection_db.json``: detection features and packer metadata.
    - ``dynamic_profiles.json``: Frida profile outcome statistics.
    - ``gui_strategies.json``: GUI reconstruction strategy outcome statistics.
    - ``sessions.json``: historical session summaries.
    """

    def __init__(self, root: str | Path = "evolution"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.knowledge_path = self.root / "knowledge_base.json"
        self.detection_path = self.root / "detection_db.json"
        self.dynamic_profiles_path = self.root / "dynamic_profiles.json"
        self.gui_strategies_path = self.root / "gui_strategies.json"
        self.sessions_path = self.root / "sessions.json"
        self._ensure_files()

    def upsert_sample(
        self,
        sample_id: str,
        *,
        features: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        observations: Optional[Iterable[Dict[str, Any] | str]] = None,
    ) -> Dict[str, Any]:
        kb = self.load_knowledge()
        samples = kb.setdefault("samples", {})
        existing = dict(samples.get(sample_id, {}))
        created_at = existing.get("created_at", utc_now())
        merged_features = dict(existing.get("features", {}))
        merged_features.update(features or {})
        merged_metadata = dict(existing.get("metadata", {}))
        merged_metadata.update(metadata or {})
        merged_observations = list(existing.get("observations", []))
        for observation in observations or []:
            merged_observations.append(self._observation_record(observation))
        record = {
            "sample_id": sample_id,
            "features": merged_features,
            "metadata": merged_metadata,
            "observations": merged_observations,
            "created_at": created_at,
            "updated_at": utc_now(),
        }
        samples[sample_id] = record
        kb["last_updated"] = record["updated_at"]
        self.save_knowledge(kb)
        self._mirror_features_to_detection_db(sample_id, merged_features)
        return record

    def add_observation(
        self,
        sample_id: str,
        observation: Dict[str, Any] | str,
    ) -> Dict[str, Any]:
        kb = self.load_knowledge()
        samples = kb.setdefault("samples", {})
        if sample_id not in samples:
            samples[sample_id] = {
                "sample_id": sample_id,
                "features": {},
                "metadata": {},
                "observations": [],
                "created_at": utc_now(),
                "updated_at": utc_now(),
            }
        record = self._observation_record(observation)
        samples[sample_id].setdefault("observations", []).append(record)
        samples[sample_id]["updated_at"] = utc_now()
        kb["last_updated"] = samples[sample_id]["updated_at"]
        self.save_knowledge(kb)
        return record

    def find_similar_by_feature(
        self,
        features: Dict[str, Any],
        *,
        min_score: float = 0.1,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        desired = self._flatten_features(features)
        if not desired:
            return []
        kb = self.load_knowledge()
        matches: list[Dict[str, Any]] = []
        for sample_id, sample in kb.get("samples", {}).items():
            sample_features = self._flatten_features(sample.get("features", {}))
            if not sample_features:
                continue
            intersection = desired & sample_features
            union = desired | sample_features
            score = len(intersection) / len(union) if union else 0.0
            if score >= min_score:
                matches.append({
                    "sample_id": sample_id,
                    "score": score,
                    "matched_features": sorted(intersection),
                    "sample": sample,
                })
        matches.sort(key=lambda item: (-item["score"], item["sample_id"]))
        return matches[:limit] if limit is not None else matches

    def load_knowledge(self) -> Dict[str, Any]:
        return self._read_json(self.knowledge_path, default={"version": 1, "samples": {}})

    def save_knowledge(self, data: Dict[str, Any]) -> None:
        self._write_json(self.knowledge_path, data)

    def load_detection_db(self) -> Dict[str, Any]:
        return self._read_json(self.detection_path, default={})

    def save_detection_db(self, data: Dict[str, Any]) -> None:
        self._write_json(self.detection_path, data)

    def load_sessions(self) -> Any:
        return self._read_json(self.sessions_path, default=[])

    def save_sessions(self, data: Any) -> None:
        self._write_json(self.sessions_path, data)

    def append_session_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        sessions = self.load_sessions()
        if not isinstance(sessions, list):
            sessions = []
        item = {"timestamp": utc_now(), **summary}
        sessions.append(item)
        self.save_sessions(sessions)
        return item

    def record_dynamic_profile_result(
        self,
        profile: str,
        *,
        backend: str = "frida",
        status: str = "unknown",
        event_count: int = 0,
        return_event_count: int = 0,
        planned_hook_count: int = 0,
        category_counts: Optional[Dict[str, Any]] = None,
        sample_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Accumulate outcome statistics for a dynamic-analysis profile."""

        profile_name = str(profile or "unknown").lower()
        data = self.load_dynamic_profiles()
        profiles = data.setdefault("profiles", {})
        record = dict(profiles.get(profile_name, {}))
        record.setdefault("profile", profile_name)
        record.setdefault("runs", 0)
        record.setdefault("successes", 0)
        record.setdefault("failures", 0)
        record.setdefault("unavailable", 0)
        record.setdefault("total_events", 0)
        record.setdefault("total_return_events", 0)
        record.setdefault("total_planned_hooks", 0)
        record.setdefault("category_counts", {})
        record.setdefault("backends", {})
        record.setdefault("samples", [])

        event_count_int = _int(event_count)
        return_count_int = _int(return_event_count)
        planned_hook_count_int = _int(planned_hook_count)
        status_value = str(status or "unknown").lower()
        backend_value = str(backend or "unknown").lower()

        record["runs"] = _int(record.get("runs")) + 1
        if status_value == "ok":
            record["successes"] = _int(record.get("successes")) + 1
        elif status_value == "unavailable":
            record["unavailable"] = _int(record.get("unavailable")) + 1
        elif status_value == "failed":
            record["failures"] = _int(record.get("failures")) + 1
        record["total_events"] = _int(record.get("total_events")) + event_count_int
        record["total_return_events"] = _int(record.get("total_return_events")) + return_count_int
        record["total_planned_hooks"] = _int(record.get("total_planned_hooks")) + planned_hook_count_int

        merged_categories = dict(record.get("category_counts") or {})
        for key, value in (category_counts or {}).items():
            merged_categories[str(key)] = _int(merged_categories.get(str(key))) + _int(value)
        record["category_counts"] = merged_categories

        backends = dict(record.get("backends") or {})
        backends[backend_value] = _int(backends.get(backend_value)) + 1
        record["backends"] = backends

        samples = list(record.get("samples") or [])
        if sample_id and sample_id not in samples:
            samples.append(sample_id)
        record["samples"] = samples[-25:]

        runs = max(1, _int(record.get("runs")))
        record["avg_events"] = round(_int(record.get("total_events")) / runs, 3)
        record["avg_return_events"] = round(_int(record.get("total_return_events")) / runs, 3)
        record["avg_planned_hooks"] = round(_int(record.get("total_planned_hooks")) / runs, 3)
        record["success_rate"] = round(_int(record.get("successes")) / runs, 3)
        record["last_status"] = status_value
        record["last_updated"] = utc_now()
        profiles[profile_name] = record
        data["last_updated"] = record["last_updated"]
        self.save_dynamic_profiles(data)
        return record

    def recommend_dynamic_profile(self, *, default: str = "quick") -> Dict[str, Any]:
        """Return the historically best dynamic profile by a simple utility score."""

        data = self.load_dynamic_profiles()
        candidates: list[Dict[str, Any]] = []
        for profile_name, record in (data.get("profiles") or {}).items():
            if not isinstance(record, dict):
                continue
            runs = max(1, _int(record.get("runs")))
            score = (
                float(record.get("success_rate") or 0) * 10.0
                + float(record.get("avg_events") or 0) * 0.1
                - float(record.get("avg_planned_hooks") or 0) * 0.02
                + min(2.0, runs * 0.1)
            )
            candidate = dict(record)
            candidate["profile"] = profile_name
            candidate["score"] = round(score, 3)
            candidates.append(candidate)
        if not candidates:
            return {"profile": default, "score": 0.0, "reason": "no dynamic profile history"}
        candidates.sort(key=lambda item: (-float(item.get("score") or 0), -_int(item.get("runs")), str(item.get("profile") or "")))
        best = candidates[0]
        return {
            "profile": best.get("profile"),
            "score": best.get("score"),
            "runs": best.get("runs"),
            "success_rate": best.get("success_rate"),
            "avg_events": best.get("avg_events"),
            "avg_planned_hooks": best.get("avg_planned_hooks"),
        }

    def load_dynamic_profiles(self) -> Dict[str, Any]:
        return self._read_json(self.dynamic_profiles_path, default={"version": 1, "profiles": {}})

    def save_dynamic_profiles(self, data: Dict[str, Any]) -> None:
        self._write_json(self.dynamic_profiles_path, data)

    def record_gui_strategy_result(
        self,
        framework: str,
        strategy: str,
        *,
        status: str = "unknown",
        visual_similarity: float = 0.0,
        control_match_rate: float = 0.0,
        text_match_rate: float = 0.0,
        sample_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Accumulate fidelity outcomes for a GUI reconstruction strategy.

        The metrics are intentionally optional: an analysis run that can only
        fingerprint and select a strategy is still useful training data, while
        later visual-regression runs enrich the same aggregate record.
        """

        framework_name = str(framework or "unknown").strip().lower() or "unknown"
        strategy_name = str(strategy or "manual_assisted_visual_reconstruction").strip()
        key = strategy_name if strategy_name.startswith(f"{framework_name}:") else f"{framework_name}:{strategy_name}"
        data = self.load_gui_strategies()
        strategies = data.setdefault("strategies", {})
        record = dict(strategies.get(key, {}))
        record.setdefault("framework", framework_name)
        record.setdefault("strategy", strategy_name)
        record.setdefault("runs", 0)
        record.setdefault("successes", 0)
        record.setdefault("failures", 0)
        record.setdefault("unavailable", 0)
        record.setdefault("total_visual_similarity", 0.0)
        record.setdefault("total_control_match_rate", 0.0)
        record.setdefault("total_text_match_rate", 0.0)
        record.setdefault("samples", [])

        status_value = str(status or "unknown").lower()
        record["runs"] = _int(record.get("runs")) + 1
        if status_value == "ok":
            record["successes"] = _int(record.get("successes")) + 1
        elif status_value == "unavailable":
            record["unavailable"] = _int(record.get("unavailable")) + 1
        elif status_value == "failed":
            record["failures"] = _int(record.get("failures")) + 1

        record["total_visual_similarity"] = _float(record.get("total_visual_similarity")) + max(0.0, min(1.0, _float(visual_similarity)))
        record["total_control_match_rate"] = _float(record.get("total_control_match_rate")) + max(0.0, min(1.0, _float(control_match_rate)))
        record["total_text_match_rate"] = _float(record.get("total_text_match_rate")) + max(0.0, min(1.0, _float(text_match_rate)))

        samples = list(record.get("samples") or [])
        if sample_id and sample_id not in samples:
            samples.append(sample_id)
        record["samples"] = samples[-25:]

        runs = max(1, _int(record.get("runs")))
        record["avg_visual_similarity"] = round(_float(record.get("total_visual_similarity")) / runs, 3)
        record["avg_control_match_rate"] = round(_float(record.get("total_control_match_rate")) / runs, 3)
        record["avg_text_match_rate"] = round(_float(record.get("total_text_match_rate")) / runs, 3)
        record["success_rate"] = round(_int(record.get("successes")) / runs, 3)
        record["last_status"] = status_value
        record["last_updated"] = utc_now()
        strategies[key] = record
        data["last_updated"] = record["last_updated"]
        self.save_gui_strategies(data)
        return record

    def recommend_gui_strategy(
        self,
        *,
        framework: Optional[str] = None,
        default: str = "manual_assisted_visual_reconstruction",
    ) -> Dict[str, Any]:
        """Return the highest-value learned strategy, optionally per framework."""

        requested_framework = str(framework or "").strip().lower()
        data = self.load_gui_strategies()
        candidates: list[Dict[str, Any]] = []
        for strategy_key, record in (data.get("strategies") or {}).items():
            if not isinstance(record, dict):
                continue
            record_framework = str(record.get("framework") or strategy_key.split(":", 1)[0] or "unknown").lower()
            if requested_framework and record_framework != requested_framework:
                continue
            runs = max(1, _int(record.get("runs")))
            score = (
                _float(record.get("success_rate")) * 10.0
                + _float(record.get("avg_visual_similarity")) * 5.0
                + _float(record.get("avg_control_match_rate")) * 2.0
                + _float(record.get("avg_text_match_rate")) * 2.0
                + min(2.0, runs * 0.1)
            )
            candidate = dict(record)
            candidate["framework"] = record_framework
            candidate["strategy"] = str(record.get("strategy") or strategy_key.split(":", 1)[-1])
            candidate["score"] = round(score, 3)
            candidates.append(candidate)
        if not candidates:
            return {
                "framework": requested_framework or None,
                "strategy": default,
                "score": 0.0,
                "reason": "no GUI strategy history",
            }
        candidates.sort(
            key=lambda item: (
                -_float(item.get("score")),
                -_int(item.get("runs")),
                str(item.get("framework") or ""),
                str(item.get("strategy") or ""),
            )
        )
        best = candidates[0]
        return {
            "framework": best.get("framework"),
            "strategy": best.get("strategy"),
            "score": best.get("score"),
            "runs": best.get("runs"),
            "success_rate": best.get("success_rate"),
            "avg_visual_similarity": best.get("avg_visual_similarity"),
            "avg_control_match_rate": best.get("avg_control_match_rate"),
            "avg_text_match_rate": best.get("avg_text_match_rate"),
        }

    def load_gui_strategies(self) -> Dict[str, Any]:
        return self._read_json(self.gui_strategies_path, default={"version": 1, "strategies": {}})

    def save_gui_strategies(self, data: Dict[str, Any]) -> None:
        self._write_json(self.gui_strategies_path, data)

    def _ensure_files(self) -> None:
        if not self.knowledge_path.exists():
            self._write_json(self.knowledge_path, {"version": 1, "samples": {}, "last_updated": utc_now()})
        else:
            kb = self._read_json(self.knowledge_path, default={})
            if "samples" not in kb:
                kb.setdefault("samples", {})
                self._write_json(self.knowledge_path, kb)
        if not self.detection_path.exists():
            self._write_json(self.detection_path, {})
        if not self.dynamic_profiles_path.exists():
            self._write_json(self.dynamic_profiles_path, {"version": 1, "profiles": {}, "last_updated": utc_now()})
        if not self.gui_strategies_path.exists():
            self._write_json(self.gui_strategies_path, {"version": 1, "strategies": {}, "last_updated": utc_now()})
        if not self.sessions_path.exists():
            self._write_json(self.sessions_path, [])

    def _mirror_features_to_detection_db(self, sample_id: str, features: Dict[str, Any]) -> None:
        detection = self.load_detection_db()
        samples = detection.setdefault("samples", {})
        samples[sample_id] = {"features": features, "updated_at": utc_now()}
        self.save_detection_db(detection)

    @staticmethod
    def _observation_record(observation: Dict[str, Any] | str) -> Dict[str, Any]:
        if isinstance(observation, str):
            return {"timestamp": utc_now(), "message": observation, "data": {}}
        record = dict(observation)
        record.setdefault("timestamp", utc_now())
        return record

    @staticmethod
    def _flatten_features(features: Dict[str, Any]) -> set[str]:
        flattened: set[str] = set()
        for key, value in features.items():
            if isinstance(value, dict):
                for subkey, subvalue in value.items():
                    flattened.add(f"{key}.{subkey}={subvalue}")
            elif isinstance(value, (list, tuple, set)):
                for item in value:
                    flattened.add(f"{key}={item}")
            else:
                flattened.add(f"{key}={value}")
        return flattened

    @staticmethod
    def _read_json(path: Path, *, default: Any) -> Any:
        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except FileNotFoundError:
            return default
        except json.JSONDecodeError:
            return default

    @staticmethod
    def _write_json(path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + ".tmp")
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        temp.replace(path)
