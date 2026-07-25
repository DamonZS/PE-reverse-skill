"""Knowledge-base persistence for reverse-analysis evolution data."""

from __future__ import annotations

import json
import math
import re
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from reverse_analyzer.core.models import utc_now
from reverse_analyzer.knowledge.capability_outcomes import CapabilityOutcomeKnowledgeMixin
from reverse_analyzer.knowledge.strategy_stats import (
    default_strategy_store,
    normalize_strategy_status as _normalize_strategy_status_impl,
    record_strategy_result as _record_strategy_result_impl,
    recommend_strategy as _recommend_strategy_impl,
)


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class KnowledgeBase(CapabilityOutcomeKnowledgeMixin):
    """Read/write helper for evolution JSON databases.

    Files managed under ``root``:
    - ``knowledge_base.json``: sample records and observations.
    - ``detection_db.json``: detection features and packer metadata.
    - ``dynamic_profiles.json``: Frida profile outcome statistics.
    - ``gui_strategies.json``: GUI reconstruction strategy outcome statistics.
    - ``patch_strategies.json``: patch lifecycle strategy outcome statistics.
    - ``llm_jailbreak_strategies.json``: model jailbreak strategy outcomes.
    - ``sessions.json``: historical session summaries.
    """

    def __init__(self, root: str | Path = "evolution"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.knowledge_path = self.root / "knowledge_base.json"
        self.detection_path = self.root / "detection_db.json"
        self.dynamic_profiles_path = self.root / "dynamic_profiles.json"
        self.gui_strategies_path = self.root / "gui_strategies.json"
        self.patch_strategies_path = self.root / "patch_strategies.json"
        self.engine_strategies_path = self.root / "engine_strategies.json"
        self.protocol_formats_path = self.root / "protocol_formats.json"
        self.source_restoration_path = self.root / "source_restoration.json"
        self.llm_jailbreak_strategies_path = self.root / "llm_jailbreak_strategies.json"
        self.sessions_path = self.root / "sessions.json"
        self.documents_path = self.root / "knowledge_documents.json"
        self._strategy_namespace_paths = {
            "gui": self.gui_strategies_path,
            "patch": self.patch_strategies_path,
            "engine": self.engine_strategies_path,
            "protocol": self.protocol_formats_path,
            "source": self.source_restoration_path,
        }
        self._ensure_files()

    def add_document(
        self,
        content: str,
        *,
        document_type: str = "memory",
        title: Optional[str] = None,
        scope: str = "global",
        tags: Optional[Iterable[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        document_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persist reusable analysis knowledge using PentAGI-style typed documents."""

        normalized_content = str(content or "").strip()
        if not normalized_content:
            raise ValueError("knowledge document content must not be empty")
        normalized_type = str(document_type or "memory").strip().lower()
        if normalized_type not in {"memory", "guide", "answer", "code"}:
            raise ValueError("knowledge document type must be one of: memory, guide, answer, code")
        normalized_scope = str(scope or "global").strip() or "global"
        normalized_tags = sorted(
            {str(tag).strip().lower() for tag in (tags or []) if str(tag).strip()}
        )
        data = self.load_documents()
        documents = data.setdefault("documents", {})
        identifier = str(document_id or uuid.uuid4().hex).strip()
        existing = documents.get(identifier)
        created_at = existing.get("created_at") if isinstance(existing, dict) else None
        timestamp = utc_now()
        record = {
            "id": identifier,
            "type": normalized_type,
            "title": str(title or "").strip(),
            "content": normalized_content,
            "scope": normalized_scope,
            "tags": normalized_tags,
            "metadata": dict(metadata or {}),
            "created_at": created_at or timestamp,
            "updated_at": timestamp,
        }
        documents[identifier] = record
        data["last_updated"] = timestamp
        self.save_documents(data)
        return record

    def load_documents(self) -> Dict[str, Any]:
        default = {"version": 1, "documents": {}}
        data = self._read_json(self.documents_path, default=default)
        if not isinstance(data, dict):
            return default
        data.setdefault("version", 1)
        if not isinstance(data.get("documents"), dict):
            data["documents"] = {}
        return data

    def save_documents(self, data: Dict[str, Any]) -> None:
        self._write_json(self.documents_path, data)

    def list_documents(
        self,
        *,
        document_type: Optional[str] = None,
        scope: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        required_tags = {str(tag).strip().lower() for tag in (tags or []) if str(tag).strip()}
        records = []
        for document in self.load_documents()["documents"].values():
            if not isinstance(document, dict):
                continue
            if document_type and document.get("type") != str(document_type).strip().lower():
                continue
            if scope and document.get("scope") != str(scope).strip():
                continue
            if required_tags - set(document.get("tags") or []):
                continue
            records.append(dict(document))
        records.sort(key=lambda item: (str(item.get("updated_at") or ""), str(item.get("id") or "")), reverse=True)
        return records[:limit] if limit is not None else records

    def search_documents(
        self,
        query: str,
        *,
        document_type: Optional[str] = None,
        scope: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        limit: int = 5,
        min_score: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Rank typed documents using dependency-free weighted token overlap."""

        query_tokens = self._knowledge_tokens(query)
        if not query_tokens:
            return []
        matches = []
        for document in self.list_documents(document_type=document_type, scope=scope, tags=tags):
            title_tokens = self._knowledge_tokens(document.get("title"))
            tag_tokens = self._knowledge_tokens(" ".join(document.get("tags") or []))
            content_tokens = self._knowledge_tokens(document.get("content"))
            weighted_overlap = (
                3.0 * len(query_tokens & title_tokens)
                + 2.0 * len(query_tokens & tag_tokens)
                + len(query_tokens & content_tokens)
            )
            score = weighted_overlap / (6.0 * len(query_tokens))
            if score <= min_score:
                continue
            matches.append({"score": round(score, 4), "document": document})
        matches.sort(key=lambda item: float(item["score"]), reverse=True)
        return matches[:max(0, limit)]

    @staticmethod
    def _knowledge_tokens(value: Any) -> set[str]:
        return {
            token.lower()
            for token in re.findall(r"[A-Za-z0-9_]{2,}|[\u4e00-\u9fff]", str(value or ""))
        }

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

    def load_llm_jailbreak_strategies(self) -> Dict[str, Any]:
        default = {"version": 1, "strategies": {}}
        data = self._read_json(self.llm_jailbreak_strategies_path, default=default)
        if not isinstance(data, dict):
            return default
        data.setdefault("version", 1)
        if not isinstance(data.get("strategies"), dict):
            data["strategies"] = {}
        return data

    def save_llm_jailbreak_strategies(self, data: Dict[str, Any]) -> None:
        self._write_json(self.llm_jailbreak_strategies_path, data)

    def record_llm_jailbreak_strategy_result(
        self,
        strategy: str,
        *,
        model: str = "unknown",
        status: str = "unknown",
        score: float = 0.0,
        attempts: int = 0,
        latency_ms: float = 0.0,
        sample_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Accumulate jailbreak outcomes globally and for each target model."""

        strategy_name = str(strategy or "unknown").strip().lower() or "unknown"
        model_name = str(model or "unknown").strip().lower() or "unknown"
        status_value = self._normalize_llm_jailbreak_status(status)
        score_value = min(1.0, max(0.0, self._finite_number(score)))
        attempts_value = max(0, _int(attempts))
        latency_value = max(0.0, self._finite_number(latency_ms))

        data = self.load_llm_jailbreak_strategies()
        strategies = data.setdefault("strategies", {})
        existing = strategies.get(strategy_name)
        record = dict(existing) if isinstance(existing, dict) else {}
        record["strategy"] = strategy_name
        self._update_llm_jailbreak_bucket(
            record,
            status=status_value,
            score=score_value,
            attempts=attempts_value,
            latency_ms=latency_value,
        )

        raw_models = record.get("models")
        models = {
            str(name).strip().lower(): max(0, _int(count))
            for name, count in raw_models.items()
            if str(name).strip()
        } if isinstance(raw_models, dict) else {}
        models[model_name] = models.get(model_name, 0) + 1
        record["models"] = models

        raw_model_stats = record.get("model_stats")
        model_stats = dict(raw_model_stats) if isinstance(raw_model_stats, dict) else {}
        existing_model_record = model_stats.get(model_name)
        model_record = dict(existing_model_record) if isinstance(existing_model_record, dict) else {}
        model_record["model"] = model_name
        self._update_llm_jailbreak_bucket(
            model_record,
            status=status_value,
            score=score_value,
            attempts=attempts_value,
            latency_ms=latency_value,
        )

        sample_value = str(sample_id).strip() if sample_id not in (None, "") else ""
        samples = record.get("samples")
        recent_samples = list(samples) if isinstance(samples, list) else []
        model_samples = model_record.get("samples")
        recent_model_samples = list(model_samples) if isinstance(model_samples, list) else []
        if sample_value:
            recent_samples = [item for item in recent_samples if item != sample_value]
            recent_samples.append(sample_value)
            recent_model_samples = [item for item in recent_model_samples if item != sample_value]
            recent_model_samples.append(sample_value)
        record["samples"] = recent_samples[-25:]
        model_record["samples"] = recent_model_samples[-25:]
        model_stats[model_name] = model_record
        record["model_stats"] = model_stats

        timestamp = utc_now()
        record["last_status"] = status_value
        record["last_model"] = model_name
        record["last_updated"] = timestamp
        model_record["last_status"] = status_value
        model_record["last_updated"] = timestamp
        strategies[strategy_name] = record
        data["last_updated"] = timestamp
        self.save_llm_jailbreak_strategies(data)
        return record

    def recommend_llm_jailbreak_strategy(
        self,
        *,
        model: Optional[str] = None,
        default: str = "adaptive",
    ) -> Dict[str, Any]:
        """Recommend a strategy using outcome quality, cost, and stability."""

        requested_model = str(model or "").strip().lower()
        candidates: list[Dict[str, Any]] = []
        strategies = self.load_llm_jailbreak_strategies().get("strategies") or {}
        for strategy_key, record in strategies.items():
            if not isinstance(record, dict):
                continue
            strategy_name = str(record.get("strategy") or strategy_key).strip().lower()
            scoped_record = record
            if requested_model:
                model_stats = record.get("model_stats")
                scoped = None
                if isinstance(model_stats, dict):
                    scoped = next(
                        (
                            value
                            for name, value in model_stats.items()
                            if str(name).strip().lower() == requested_model
                        ),
                        None,
                    )
                if isinstance(scoped, dict):
                    scoped_record = scoped
                else:
                    models = record.get("models")
                    model_runs = sum(
                        max(0, _int(count))
                        for name, count in models.items()
                        if str(name).strip().lower() == requested_model
                    ) if isinstance(models, dict) else 0
                    if model_runs <= 0:
                        continue

            metrics = self._llm_jailbreak_bucket_metrics(scoped_record)
            runs = metrics["runs"]
            if runs <= 0:
                continue
            unavailable_rate = metrics["unavailable"] / runs
            stability = min(2.0, math.log2(runs + 1) * 0.5) * (1.0 - unavailable_rate)
            attempt_penalty = min(3.0, metrics["avg_attempts"] * 0.25)
            latency_penalty = min(2.0, metrics["avg_latency_ms"] / 20000.0)
            utility = (
                metrics["success_rate"] * 10.0
                + metrics["avg_score"] * 5.0
                + stability
                - attempt_penalty
                - latency_penalty
            )
            candidates.append(
                {
                    "model": requested_model or None,
                    "strategy": strategy_name,
                    "score": round(utility, 3),
                    "runs": runs,
                    "success_rate": round(metrics["success_rate"], 3),
                    "avg_score": round(metrics["avg_score"], 3),
                    "avg_attempts": round(metrics["avg_attempts"], 3),
                    "avg_latency_ms": round(metrics["avg_latency_ms"], 3),
                    "stability_score": round(stability, 3),
                    "models": dict(record.get("models") or {})
                    if isinstance(record.get("models"), dict)
                    else {},
                    "samples": list(scoped_record.get("samples") or [])
                    if isinstance(scoped_record.get("samples"), list)
                    else [],
                }
            )

        if not candidates:
            return {
                "model": requested_model or None,
                "strategy": str(default or "adaptive").strip() or "adaptive",
                "score": 0.0,
                "reason": "no LLM jailbreak strategy history",
            }
        candidates.sort(
            key=lambda item: (
                -self._finite_number(item.get("score"), default=float("-inf")),
                -self._finite_number(item.get("success_rate")),
                -_int(item.get("runs")),
                str(item.get("strategy") or ""),
            )
        )
        return candidates[0]

    @staticmethod
    def _normalize_llm_jailbreak_status(status: Any) -> str:
        normalized = "_".join(
            str(status or "unknown").strip().lower().replace("-", "_").split()
        )
        if normalized in {"jailbroken", "bypassed", "breakthrough", "compromised"}:
            return "ok"
        if normalized in {"blocked", "refused", "rejected", "failure", "failed", "error"}:
            return "failed"
        return _normalize_strategy_status_impl(normalized)

    @staticmethod
    def _finite_number(value: Any, *, default: float = 0.0) -> float:
        if isinstance(value, bool):
            return default
        number = _float(value, default)
        return number if math.isfinite(number) else default

    @classmethod
    def _update_llm_jailbreak_bucket(
        cls,
        bucket: Dict[str, Any],
        *,
        status: str,
        score: float,
        attempts: int,
        latency_ms: float,
    ) -> None:
        bucket["runs"] = max(0, _int(bucket.get("runs"))) + 1
        bucket["successes"] = max(0, _int(bucket.get("successes")))
        bucket["failures"] = max(0, _int(bucket.get("failures")))
        bucket["unavailable"] = max(0, _int(bucket.get("unavailable")))
        if status == "ok":
            bucket["successes"] += 1
        elif status == "unavailable":
            bucket["unavailable"] += 1
        else:
            bucket["failures"] += 1

        bucket["total_score"] = max(0.0, cls._finite_number(bucket.get("total_score"))) + score
        bucket["total_attempts"] = max(0, _int(bucket.get("total_attempts"))) + attempts
        bucket["total_latency_ms"] = max(
            0.0,
            cls._finite_number(bucket.get("total_latency_ms")),
        ) + latency_ms
        runs = bucket["runs"]
        bucket["success_rate"] = round(bucket["successes"] / runs, 3)
        bucket["avg_score"] = round(bucket["total_score"] / runs, 3)
        bucket["avg_attempts"] = round(bucket["total_attempts"] / runs, 3)
        bucket["avg_latency_ms"] = round(bucket["total_latency_ms"] / runs, 3)

    @classmethod
    def _llm_jailbreak_bucket_metrics(cls, bucket: Dict[str, Any]) -> Dict[str, float | int]:
        runs = max(0, _int(bucket.get("runs")))
        successes = max(0, min(runs, _int(bucket.get("successes"))))
        unavailable = max(0, min(runs, _int(bucket.get("unavailable"))))
        success_rate = successes / runs if runs else 0.0
        if "successes" not in bucket:
            success_rate = min(1.0, max(0.0, cls._finite_number(bucket.get("success_rate"))))
        return {
            "runs": runs,
            "unavailable": unavailable,
            "success_rate": success_rate,
            "avg_score": min(1.0, max(0.0, cls._finite_number(bucket.get("avg_score")))),
            "avg_attempts": max(0.0, cls._finite_number(bucket.get("avg_attempts"))),
            "avg_latency_ms": max(0.0, cls._finite_number(bucket.get("avg_latency_ms"))),
        }

    def load_patch_strategies(self) -> Dict[str, Any]:
        data = self._read_json(
            self.patch_strategies_path,
            default={"version": 1, "strategies": {}},
        )
        if not isinstance(data, dict):
            return {"version": 1, "strategies": {}}
        data.setdefault("version", 1)
        if not isinstance(data.get("strategies"), dict):
            data["strategies"] = {}
        return data

    def save_patch_strategies(self, data: Dict[str, Any]) -> None:
        self._write_json(self.patch_strategies_path, data)

    def record_patch_strategy_result(
        self,
        strategy: str,
        *,
        target_format: str = "pe",
        status: str = "unknown",
        verification_status: Optional[str] = None,
        apply_status: Optional[str] = None,
        rollback_status: Optional[str] = None,
        operation_count: int = 0,
        risk_counts: Optional[Dict[str, Any]] = None,
        sample_id: Optional[str] = None,
        backend: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Accumulate verified patch lifecycle outcomes for one strategy."""

        format_name = str(target_format or "unknown").strip().lower() or "unknown"
        strategy_name = str(strategy or "inline_patch").strip().lower() or "inline_patch"
        key = strategy_name if strategy_name.startswith(f"{format_name}:") else f"{format_name}:{strategy_name}"
        stored_strategy = strategy_name.split(":", 1)[-1] if strategy_name.startswith(f"{format_name}:") else strategy_name

        data = self.load_patch_strategies()
        strategies = data.setdefault("strategies", {})
        record = dict(strategies.get(key, {}))
        record.setdefault("target_format", format_name)
        record.setdefault("strategy", stored_strategy)
        record.setdefault("runs", 0)
        record.setdefault("successes", 0)
        record.setdefault("failures", 0)
        record.setdefault("unavailable", 0)
        record.setdefault("verifications_attempted", 0)
        record.setdefault("verifications_passed", 0)
        record.setdefault("applies_attempted", 0)
        record.setdefault("applies_succeeded", 0)
        record.setdefault("rollbacks_attempted", 0)
        record.setdefault("rollbacks_succeeded", 0)
        record.setdefault("total_operation_count", 0)
        record.setdefault("risk_counts", {})
        record.setdefault("backends", {})
        record.setdefault("samples", [])

        status_value = str(status or "unknown").strip().lower() or "unknown"
        record["runs"] = _int(record.get("runs")) + 1
        if status_value in {"ok", "success", "succeeded", "passed", "planned"}:
            record["successes"] = _int(record.get("successes")) + 1
        elif status_value in {"unavailable", "unsupported", "skipped"}:
            record["unavailable"] = _int(record.get("unavailable")) + 1
        elif status_value in {"failed", "failure", "error"}:
            record["failures"] = _int(record.get("failures")) + 1

        self._record_patch_stage(record, "verification", verification_status)
        self._record_patch_stage(record, "apply", apply_status)
        self._record_patch_stage(record, "rollback", rollback_status)
        record["total_operation_count"] = _int(record.get("total_operation_count")) + max(
            0,
            _int(operation_count),
        )

        aggregate_risks = dict(record.get("risk_counts") or {})
        for risk, count in (risk_counts or {}).items():
            risk_name = str(risk or "unknown").strip().lower() or "unknown"
            aggregate_risks[risk_name] = _int(aggregate_risks.get(risk_name)) + max(0, _int(count))
        record["risk_counts"] = aggregate_risks

        if backend:
            backend_name = str(backend).strip().lower()
            if backend_name:
                backends = dict(record.get("backends") or {})
                backends[backend_name] = _int(backends.get(backend_name)) + 1
                record["backends"] = backends

        samples = [item for item in (record.get("samples") or []) if item != sample_id]
        if sample_id:
            samples.append(sample_id)
        record["samples"] = samples[-25:]

        runs = max(1, _int(record.get("runs")))
        verification_attempts = _int(record.get("verifications_attempted"))
        apply_attempts = _int(record.get("applies_attempted"))
        rollback_attempts = _int(record.get("rollbacks_attempted"))
        record["success_rate"] = round(_int(record.get("successes")) / runs, 3)
        record["verify_rate"] = round(
            _int(record.get("verifications_passed")) / verification_attempts,
            3,
        ) if verification_attempts else 0.0
        record["apply_rate"] = round(
            _int(record.get("applies_succeeded")) / apply_attempts,
            3,
        ) if apply_attempts else 0.0
        record["rollback_rate"] = round(
            _int(record.get("rollbacks_succeeded")) / rollback_attempts,
            3,
        ) if rollback_attempts else 0.0
        record["avg_operation_count"] = round(_int(record.get("total_operation_count")) / runs, 3)
        record["last_status"] = status_value
        record["last_updated"] = utc_now()
        strategies[key] = record
        data["last_updated"] = record["last_updated"]
        self.save_patch_strategies(data)
        return record

    def recommend_patch_strategy(
        self,
        *,
        target_format: Optional[str] = None,
        default: str = "inline_patch",
    ) -> Dict[str, Any]:
        """Return the strongest learned patch strategy for a target format."""

        requested_format = str(target_format or "").strip().lower()
        candidates: list[Dict[str, Any]] = []
        for strategy_key, record in (self.load_patch_strategies().get("strategies") or {}).items():
            if not isinstance(record, dict):
                continue
            record_format = str(
                record.get("target_format") or str(strategy_key).split(":", 1)[0] or "unknown"
            ).lower()
            if requested_format and record_format != requested_format:
                continue
            runs = max(1, _int(record.get("runs")))
            risk_penalty = self._patch_risk_penalty(record.get("risk_counts"), runs=runs)
            score = (
                _float(record.get("success_rate")) * 10.0
                + _float(record.get("verify_rate")) * 2.0
                + _float(record.get("apply_rate")) * 3.0
                + _float(record.get("rollback_rate")) * 1.5
                + min(2.0, runs * 0.1)
                - risk_penalty
                - min(1.0, _float(record.get("avg_operation_count")) * 0.01)
            )
            candidate = dict(record)
            candidate["target_format"] = record_format
            candidate["strategy"] = str(record.get("strategy") or str(strategy_key).split(":", 1)[-1])
            candidate["score"] = round(score, 3)
            candidates.append(candidate)

        if not candidates:
            return {
                "target_format": requested_format or None,
                "strategy": default,
                "score": 0.0,
                "reason": "no patch strategy history",
            }
        candidates.sort(
            key=lambda item: (
                -_float(item.get("score")),
                -_int(item.get("runs")),
                str(item.get("target_format") or ""),
                str(item.get("strategy") or ""),
            )
        )
        best = candidates[0]
        return {
            "target_format": best.get("target_format"),
            "strategy": best.get("strategy"),
            "score": best.get("score"),
            "runs": best.get("runs"),
            "success_rate": best.get("success_rate"),
            "verify_rate": best.get("verify_rate"),
            "apply_rate": best.get("apply_rate"),
            "rollback_rate": best.get("rollback_rate"),
            "avg_operation_count": best.get("avg_operation_count"),
            "risk_counts": dict(best.get("risk_counts") or {}),
        }

    @staticmethod
    def _record_patch_stage(record: Dict[str, Any], stage: str, status: Optional[str]) -> None:
        status_value = str(status or "").strip().lower()
        if not status_value or status_value in {"unknown", "pending", "not_run", "not_attempted"}:
            return
        attempted_key = {
            "verification": "verifications_attempted",
            "apply": "applies_attempted",
            "rollback": "rollbacks_attempted",
        }[stage]
        succeeded_key = {
            "verification": "verifications_passed",
            "apply": "applies_succeeded",
            "rollback": "rollbacks_succeeded",
        }[stage]
        record[attempted_key] = _int(record.get(attempted_key)) + 1
        if status_value in {"ok", "success", "succeeded", "passed", "restored"}:
            record[succeeded_key] = _int(record.get(succeeded_key)) + 1

    @staticmethod
    def _patch_risk_penalty(risk_counts: Any, *, runs: int) -> float:
        if not isinstance(risk_counts, dict):
            return 0.0
        weights = {
            "critical": 4.0,
            "high": 2.0,
            "medium": 0.5,
            "warning": 0.25,
            "low": 0.1,
            "info": 0.0,
        }
        weighted = sum(
            weights.get(str(risk).lower(), 0.25) * max(0, _int(count))
            for risk, count in risk_counts.items()
        )
        return min(6.0, weighted / max(1, runs))


    def _load_strategy_namespace(self, namespace: str) -> Dict[str, Any]:
        path = self._strategy_namespace_paths[namespace]
        if not path.exists():
            return default_strategy_store()
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            return default_strategy_store()
        if not isinstance(data, dict):
            return default_strategy_store()
        if not isinstance(data.get("strategies"), dict):
            data["strategies"] = {}
        return data

    def _save_strategy_namespace(self, namespace: str, data: Dict[str, Any]) -> None:
        path = self._strategy_namespace_paths[namespace]
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.write("\n")

    def record_strategy_result(
        self,
        namespace: str,
        key: str,
        status: str,
        metrics: Optional[Dict[str, Any]] = None,
        sample_id: Optional[str] = None,
        backend: Optional[str] = None,
    ) -> Dict[str, Any]:
        namespace_name = str(namespace or "").strip().lower()
        if namespace_name not in self._strategy_namespace_paths:
            raise KeyError(f"Unknown strategy namespace: {namespace}")
        strategy_key = str(key or "").strip()
        if not strategy_key:
            raise ValueError("Strategy key must not be empty")

        data = self._load_strategy_namespace(namespace_name)
        self._normalize_strategy_bucket(data, strategy_key)
        result = _record_strategy_result_impl(
            data,
            key=strategy_key,
            status=self._normalize_strategy_status(status),
            metrics=self._normalize_strategy_metrics(metrics),
            sample_id=str(sample_id) if sample_id not in (None, "") else None,
            backend=str(backend).strip().lower() if backend not in (None, "") else None,
        )
        timestamp = utc_now()
        result["last_updated"] = timestamp
        data["last_updated"] = timestamp
        self._save_strategy_namespace(namespace_name, data)
        return dict(result)

    def recommend_strategy(self, namespace: str) -> Optional[Dict[str, Any]]:
        """Return the best generic strategy with deterministic tie-breaking."""

        namespace_name = str(namespace or "").strip().lower()
        if namespace_name not in self._strategy_namespace_paths:
            raise KeyError(f"Unknown strategy namespace: {namespace}")

        data = self._load_strategy_namespace(namespace_name)
        strategies = data.get("strategies") if isinstance(data, dict) else {}
        if not isinstance(strategies, dict):
            return None
        candidates: list[Dict[str, Any]] = []
        for key in sorted(list(strategies), key=str):
            self._normalize_strategy_bucket(data, key)
            bucket = strategies.get(key)
            if not isinstance(bucket, dict):
                continue
            candidate = _recommend_strategy_impl({"strategies": {str(key): bucket}})
            if not isinstance(candidate, dict):
                continue
            score = _float(candidate.get("score"), float("-inf"))
            if not math.isfinite(score):
                continue
            candidate["key"] = str(key)
            candidates.append(candidate)
        if not candidates:
            return None
        candidates.sort(
            key=lambda item: (
                -_float(item.get("score")),
                -_int(item.get("runs")),
                str(item.get("key") or ""),
            )
        )
        return candidates[0]

    def record_engine_strategy_result(
        self,
        key: str,
        *,
        status: str = "unknown",
        metrics: Optional[Dict[str, Any]] = None,
        sample_id: Optional[str] = None,
        backend: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self.record_strategy_result(
            "engine", key, status, metrics=metrics, sample_id=sample_id, backend=backend
        )

    def recommend_engine_strategy(self) -> Optional[Dict[str, Any]]:
        return self.recommend_strategy("engine")

    def record_protocol_format_result(
        self,
        key: str,
        *,
        status: str = "unknown",
        metrics: Optional[Dict[str, Any]] = None,
        sample_id: Optional[str] = None,
        backend: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self.record_strategy_result(
            "protocol", key, status, metrics=metrics, sample_id=sample_id, backend=backend
        )

    def recommend_protocol_format(self) -> Optional[Dict[str, Any]]:
        return self.recommend_strategy("protocol")

    def record_source_restoration_result(
        self,
        key: str,
        *,
        status: str = "unknown",
        metrics: Optional[Dict[str, Any]] = None,
        sample_id: Optional[str] = None,
        backend: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self.record_strategy_result(
            "source", key, status, metrics=metrics, sample_id=sample_id, backend=backend
        )

    def recommend_source_restoration(self) -> Optional[Dict[str, Any]]:
        return self.recommend_strategy("source")

    @staticmethod
    def _normalize_strategy_status(status: Any) -> str:
        return _normalize_strategy_status_impl(status)

    @staticmethod
    def _normalize_strategy_metrics(metrics: Any) -> Dict[str, float]:
        if not isinstance(metrics, dict):
            return {}
        normalized: Dict[str, float] = {}
        for raw_name, raw_value in metrics.items():
            name = str(raw_name or "").strip()
            if not name or isinstance(raw_value, bool):
                continue
            try:
                value = float(raw_value)
            except (TypeError, ValueError):
                continue
            if math.isfinite(value):
                normalized[name] = value
        return normalized

    @staticmethod
    def _normalize_strategy_bucket(data: Dict[str, Any], key: str) -> None:
        strategies = data.setdefault("strategies", {})
        existing = strategies.get(key)
        if existing is None:
            return
        if not isinstance(existing, dict):
            strategies.pop(key, None)
            return
        for counter in ("runs", "successes", "failures", "unavailable"):
            existing[counter] = max(0, _int(existing.get(counter)))
        success_rate = _float(existing.get("success_rate"), float("nan"))
        if not math.isfinite(success_rate):
            success_rate = (
                existing["successes"] / existing["runs"]
                if existing["runs"]
                else 0.0
            )
        existing["success_rate"] = min(1.0, max(0.0, success_rate))
        if not isinstance(existing.get("samples"), list):
            existing["samples"] = []
        if not isinstance(existing.get("backends"), dict):
            existing["backends"] = {}
        else:
            existing["backends"] = {
                str(name): max(0, _int(count))
                for name, count in existing["backends"].items()
            }
        for field, value in list(existing.items()):
            if field.startswith(("total_", "avg_")):
                number = _float(value)
                existing[field] = number if math.isfinite(number) else 0.0

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
        if not self.llm_jailbreak_strategies_path.exists():
            self._write_json(
                self.llm_jailbreak_strategies_path,
                {"version": 1, "strategies": {}, "last_updated": utc_now()},
            )
        for path in (
            self.patch_strategies_path,
            self.engine_strategies_path,
            self.protocol_formats_path,
            self.source_restoration_path,
        ):
            if not path.exists():
                self._write_json(path, default_strategy_store())
        if not self.sessions_path.exists():
            self._write_json(self.sessions_path, [])
        if not self.documents_path.exists():
            self._write_json(
                self.documents_path,
                {"version": 1, "documents": {}, "last_updated": utc_now()},
            )

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
