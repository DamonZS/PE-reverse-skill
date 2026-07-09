"""Knowledge-base persistence for reverse-analysis evolution data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from reverse_analyzer.core.models import utc_now


class KnowledgeBase:
    """Read/write helper for evolution JSON databases.

    Files managed under ``root``:
    - ``knowledge_base.json``: sample records and observations.
    - ``detection_db.json``: detection features and packer metadata.
    - ``sessions.json``: historical session summaries.
    """

    def __init__(self, root: str | Path = "evolution"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.knowledge_path = self.root / "knowledge_base.json"
        self.detection_path = self.root / "detection_db.json"
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
