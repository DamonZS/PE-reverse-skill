"""Evidence-manifest construction and verification.

The manifest deliberately contains only paths relative to its output directory.
That makes an analysis package movable while retaining byte-level verification of
the artifacts it owns.  The input sample is retained as a separately hashed,
external provenance record; it is not required to remain beside a moved output
package.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping


EVIDENCE_MANIFEST_SCHEMA = "reverse_analyzer.evidence_manifest/v1"
_IDENTITY_EXCLUDED_KEYS = {
    "manifest_id",
    "created_at",
    "updated_at",
    "generated_at",
    "written_at",
    "timestamp",
}
_OK_STATUSES = {"ok", "succeeded", "success", "available", "complete", "completed"}
_UNAVAILABLE_STATUSES = {"unavailable", "skipped", "missing", "not_run", "not-run"}


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON suitable for a content-derived ID."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def sha256_file(path: str | os.PathLike[str]) -> str:
    """Hash a regular file without loading it into memory."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(
    out_dir: str | os.PathLike[str],
    artifacts: Iterable[Mapping[str, Any]] | None = None,
    *,
    sample: str | os.PathLike[str] | None = None,
    unavailable_stages: Iterable[Mapping[str, Any] | str] | None = None,
) -> dict[str, Any]:
    """Build an in-memory manifest for explicitly declared output artifacts.

    ``artifacts`` is intentionally declarative rather than an output-directory
    crawl: callers state which files are analysis evidence and their originating
    tool/trace.  Existing files receive a hash and byte size.  Missing or
    unavailable records retain provenance but never receive fabricated hashes.
    """

    root = Path(out_dir).resolve()
    artifact_records: dict[str, dict[str, Any]] = {}
    stages: list[dict[str, Any]] = [_normalize_stage(item) for item in unavailable_stages or ()]

    for candidate in artifacts or ():
        if not isinstance(candidate, Mapping):
            continue
        normalized, stage = _normalize_artifact(root, candidate)
        if stage is not None:
            stages.append(stage)
        if normalized is None:
            continue
        key = str(normalized["path"])
        existing = artifact_records.get(key)
        artifact_records[key] = _merge_artifact(existing, normalized) if existing else normalized

    normalized_artifacts = [artifact_records[key] for key in sorted(artifact_records)]
    normalized_stages = _dedupe_stages(stages)
    manifest: dict[str, Any] = {
        "schema": EVIDENCE_MANIFEST_SCHEMA,
        "hash_algorithm": "sha256",
        "root": ".",
        "sample": _sample_record(sample),
        "artifacts": normalized_artifacts,
        "derivations": _derivations(normalized_artifacts),
        "unavailable_stages": normalized_stages,
    }
    manifest["manifest_id"] = _manifest_id(manifest)
    return manifest


def write_manifest(
    manifest: Mapping[str, Any],
    path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Atomically write a manifest and return the normalized payload."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = copy.deepcopy(dict(manifest))
    payload.setdefault("schema", EVIDENCE_MANIFEST_SCHEMA)
    payload.setdefault("hash_algorithm", "sha256")
    payload["manifest_id"] = _manifest_id(payload)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(canonical_json_bytes(payload) + b"\n")
        temporary.replace(target)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)
    return payload


def load_manifest(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load a manifest, accepting a UTF-8 BOM from PowerShell if present."""

    source = Path(path)
    loaded = json.loads(source.read_text(encoding="utf-8-sig"))
    if not isinstance(loaded, Mapping):
        raise ValueError("evidence manifest root must be a JSON object")
    return dict(loaded)


def verify_manifest(manifest: str | os.PathLike[str] | Mapping[str, Any]) -> dict[str, Any]:
    """Verify manifest identity and every hash-covered artifact.

    A manifest path is resolved relative to the manifest itself, not the current
    working directory, so a complete output directory may be moved unchanged.
    External sample provenance is intentionally not a required package member.
    """

    manifest_path: Path | None = None
    try:
        if isinstance(manifest, Mapping):
            payload = dict(manifest)
            root = Path.cwd()
        else:
            manifest_path = Path(manifest).resolve()
            payload = load_manifest(manifest_path)
            root = manifest_path.parent
    except Exception as exc:  # noqa: BLE001 - verification must remain machine-readable
        return _verification_failure(
            manifest_path,
            [{"kind": "manifest_unreadable", "detail": f"{type(exc).__name__}: {exc}"}],
        )

    issues: list[dict[str, Any]] = []
    if payload.get("schema") != EVIDENCE_MANIFEST_SCHEMA:
        issues.append({"kind": "schema", "expected": EVIDENCE_MANIFEST_SCHEMA, "actual": payload.get("schema")})
    actual_id = payload.get("manifest_id")
    expected_id = _manifest_id(payload)
    if actual_id != expected_id:
        issues.append({"kind": "manifest_id", "expected": expected_id, "actual": actual_id})

    verified = 0
    skipped = 0
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        issues.append({"kind": "artifacts", "detail": "artifacts must be an array"})
        artifacts = []
    seen_paths: set[str] = set()
    for index, record in enumerate(artifacts):
        if not isinstance(record, Mapping):
            issues.append({"kind": "artifact_record", "index": index, "detail": "record must be an object"})
            continue
        relative_path = record.get("path")
        status = str(record.get("status") or "ok").lower()
        expected_hash = record.get("sha256")
        expected_size = record.get("size")
        if status not in _OK_STATUSES or not expected_hash:
            skipped += 1
            continue
        if not isinstance(relative_path, str) or not relative_path:
            issues.append({"kind": "artifact_path", "index": index, "detail": "missing relative path"})
            continue
        if relative_path in seen_paths:
            issues.append({"kind": "artifact_path", "path": relative_path, "detail": "duplicate path"})
            continue
        seen_paths.add(relative_path)
        file_path = _safe_artifact_path(root, relative_path)
        if file_path is None:
            issues.append({"kind": "artifact_path", "path": relative_path, "detail": "path escapes manifest root"})
            continue
        try:
            stat = file_path.stat()
        except FileNotFoundError:
            issues.append({"kind": "missing", "path": relative_path})
            continue
        except OSError as exc:
            issues.append({"kind": "unreadable", "path": relative_path, "detail": f"{type(exc).__name__}: {exc}"})
            continue
        if not file_path.is_file():
            issues.append({"kind": "unreadable", "path": relative_path, "detail": "not a regular file"})
            continue
        if expected_size is not None:
            try:
                if int(expected_size) != stat.st_size:
                    issues.append({"kind": "size", "path": relative_path, "expected": int(expected_size), "actual": stat.st_size})
                    continue
            except (TypeError, ValueError):
                issues.append({"kind": "size", "path": relative_path, "detail": "invalid expected size"})
                continue
        try:
            actual_hash = sha256_file(file_path)
        except OSError as exc:
            issues.append({"kind": "unreadable", "path": relative_path, "detail": f"{type(exc).__name__}: {exc}"})
            continue
        if actual_hash != expected_hash:
            issues.append({"kind": "hash", "path": relative_path, "expected": expected_hash, "actual": actual_hash})
            continue
        verified += 1

    return {
        "status": "ok" if not issues else "failed",
        "valid": not issues,
        "manifest_path": str(manifest_path) if manifest_path is not None else None,
        "manifest_id": actual_id,
        "expected_manifest_id": expected_id,
        "verified_file_count": verified,
        "skipped_file_count": skipped,
        "unavailable_stage_count": len(payload.get("unavailable_stages") or []),
        "issues": issues,
        "failures": issues,
    }


def _normalize_artifact(root: Path, candidate: Mapping[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    nested = candidate.get("data")
    source = dict(nested) if isinstance(nested, Mapping) else {}
    source.update({key: value for key, value in candidate.items() if value is not None})
    raw_path = source.get("path")
    tool = source.get("tool") or source.get("tool_name")
    status = str(source.get("status") or "ok").lower()
    stage = _stage_from_source(source, tool=tool, status=status)
    if not raw_path:
        return None, stage
    try:
        raw_candidate = Path(str(raw_path))
        artifact_path = (raw_candidate if raw_candidate.is_absolute() else root / raw_candidate).resolve()
    except OSError:
        return None, stage
    try:
        relative = artifact_path.relative_to(root)
    except ValueError:
        # Output packages must not depend on arbitrary external artifact paths.
        return None, stage
    record: dict[str, Any] = {
        "path": relative.as_posix(),
        "role": str(source.get("role") or "artifact"),
        "kind": str(source.get("kind") or "artifact"),
        "status": status,
    }
    for key in ("name", "tool", "source_trace_index", "flow", "task", "subtask"):
        value = source.get(key)
        if value is not None:
            record[key] = value
    if tool is not None:
        record["tool"] = str(tool)
    generated_by = {
        "input": "sample",
        "tool": record.get("tool") or "unknown",
    }
    if record.get("source_trace_index") is not None:
        generated_by["source_trace_index"] = record["source_trace_index"]
    record["generated_by"] = generated_by
    if status in _OK_STATUSES and artifact_path.is_file():
        record["size"] = artifact_path.stat().st_size
        record["sha256"] = sha256_file(artifact_path)
    elif status in _OK_STATUSES:
        record["status"] = "missing"
        stage = _stage_from_source(source, tool=tool, status="missing", detail="declared artifact is absent")
    return record, stage


def _merge_artifact(existing: Mapping[str, Any], incoming: Mapping[str, Any]) -> dict[str, Any]:
    """Keep the strongest record while preserving deterministic provenance."""

    current = dict(existing)
    incoming_is_hashed = bool(incoming.get("sha256"))
    current_is_hashed = bool(current.get("sha256"))
    if incoming_is_hashed and not current_is_hashed:
        current.update(incoming)
    else:
        for key, value in incoming.items():
            if key not in current or current[key] in (None, "", "unknown"):
                current[key] = value
    # Session artifact records can be created before their trace record is
    # available.  In that order the first normalized derivation has an
    # ``unknown`` tool, while the duplicate trace record carries the real
    # producer.  Merge that nested provenance explicitly instead of leaving a
    # valid-but-less-useful manifest behind.
    current_generated_by = current.get("generated_by")
    incoming_generated_by = incoming.get("generated_by")
    if isinstance(current_generated_by, Mapping) or isinstance(incoming_generated_by, Mapping):
        generated_by = dict(current_generated_by) if isinstance(current_generated_by, Mapping) else {}
        if isinstance(incoming_generated_by, Mapping):
            for key, value in incoming_generated_by.items():
                if key not in generated_by or generated_by[key] in (None, "", "unknown"):
                    generated_by[key] = value
        if current.get("tool") and generated_by.get("tool") in (None, "", "unknown"):
            generated_by["tool"] = current["tool"]
        current["generated_by"] = generated_by
    return current


def _sample_record(sample: str | os.PathLike[str] | None) -> dict[str, Any]:
    if sample is None:
        return {"status": "unavailable", "verification_scope": "external"}
    path = Path(sample)
    record: dict[str, Any] = {
        "path": str(path.resolve()),
        "verification_scope": "external",
        "status": "ok" if path.is_file() else "missing",
    }
    if path.is_file():
        record["size"] = path.stat().st_size
        record["sha256"] = sha256_file(path)
    return record


def _stage_from_source(source: Mapping[str, Any], *, tool: Any, status: str, detail: str | None = None) -> dict[str, Any] | None:
    if status not in _UNAVAILABLE_STATUSES:
        return None
    stage: dict[str, Any] = {"status": status}
    if tool is not None:
        stage["tool"] = str(tool)
    elif source.get("name"):
        stage["tool"] = str(source["name"])
    if source.get("source_trace_index") is not None:
        stage["source_trace_index"] = source["source_trace_index"]
    error = detail or source.get("error") or source.get("reason")
    if error:
        stage["reason"] = str(error)
    return stage


def _normalize_stage(stage: Mapping[str, Any] | str) -> dict[str, Any]:
    if isinstance(stage, Mapping):
        normalized = {str(key): value for key, value in stage.items() if value is not None}
        normalized.setdefault("status", "unavailable")
        return normalized
    return {"tool": str(stage), "status": "unavailable"}


def _dedupe_stages(stages: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized = [dict(item) for item in stages if item]
    unique: dict[bytes, dict[str, Any]] = {}
    for item in normalized:
        unique[canonical_json_bytes(item)] = item
    return [unique[key] for key in sorted(unique)]


def _derivations(artifacts: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    derivations: list[dict[str, Any]] = []
    for artifact in artifacts:
        derivations.append(
            {
                "from": "sample",
                "to": artifact.get("path"),
                "generated_by": dict(artifact.get("generated_by") or {}),
            }
        )
    return derivations


def _identity_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _identity_payload(item)
            for key, item in value.items()
            if str(key) not in _IDENTITY_EXCLUDED_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_identity_payload(item) for item in value]
    return value


def _manifest_id(manifest: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json_bytes(_identity_payload(manifest))).hexdigest()
    return f"sha256:{digest}"


def _safe_artifact_path(root: Path, relative_path: str) -> Path | None:
    candidate = Path(relative_path)
    if candidate.is_absolute():
        return None
    try:
        resolved = (root / candidate).resolve()
        resolved.relative_to(root.resolve())
        return resolved
    except (OSError, ValueError):
        return None


def _verification_failure(manifest_path: Path | None, issues: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "status": "failed",
        "valid": False,
        "manifest_path": str(manifest_path) if manifest_path is not None else None,
        "manifest_id": None,
        "expected_manifest_id": None,
        "verified_file_count": 0,
        "skipped_file_count": 0,
        "unavailable_stage_count": 0,
        "issues": issues,
        "failures": issues,
    }
