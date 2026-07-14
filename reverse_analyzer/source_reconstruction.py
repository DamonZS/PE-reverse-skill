"""Read-only discovery of generated source-reconstruction projects.

The dashboard must be able to describe reconstruction output without running a
sample, importing a generated project, or trusting paths embedded in reports.
This module only walks directories below a caller-supplied workspace and
normalizes the small amount of project metadata needed by the UI.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
from typing import Any, Iterable, Mapping

from .source.generator import generate_source_project as _generate_source_project
from .source.behavior_validation import (
    DEFAULT_BEHAVIOR_VALIDATION_PATH,
    validate_source_behavior,
)
from .source.equivalence import (
    DEFAULT_EQUIVALENCE_ASSESSMENT_PATH,
    EQUIVALENCE_ASSESSMENT_SCHEMA_VERSION,
    EQUIVALENCE_DIMENSIONS,
    assess_source_equivalence,
)
from .source.runtime_validation import (
    DEFAULT_RUNTIME_VALIDATION_PATH,
    validate_source_runtime,
)
from .source.validation import validate_and_write_source_project


_IGNORED_DIRECTORIES = {
    ".git",
    ".codebase-memory",
    ".reverse_analyzer",
    "__pycache__",
    "dashboard",
    "node_modules",
    "build",
    "dist",
    "bin",
    "obj",
    ".vs",
}
_SOURCE_PRIORITY_DIRECTORIES = {"src", "source", "sources", "include", "app", "lib"}
_SOURCE_LANGUAGES = {
    ".c": "c",
    ".h": "c",
    ".cc": "c++",
    ".cpp": "c++",
    ".cxx": "c++",
    ".hpp": "c++",
    ".cs": "csharp",
    ".xaml": "xaml",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "css",
    ".dart": "dart",
    ".swift": "swift",
    ".m": "objective-c",
    ".mm": "objective-c++",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".qml": "qml",
    ".ui": "qt-ui",
}
_RESOURCE_SUFFIXES = {
    ".bmp",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".png",
    ".svg",
    ".tif",
    ".tiff",
    ".webp",
    ".qrc",
    ".dfm",
    ".storyboard",
    ".xib",
}
_ENTRYPOINT_NAMES = {
    "main.c",
    "main.cc",
    "main.cpp",
    "main.cxx",
    "main.py",
    "main.swift",
    "main.dart",
    "main.js",
    "main.mjs",
    "main.ts",
    "main.tsx",
    "index.js",
    "index.ts",
    "index.tsx",
    "program.cs",
    "app.xaml",
    "mainactivity.kt",
    "mainactivity.java",
}
_BUILD_ENTRYPOINT_NAMES = {
    "cmakelists.txt",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "build.gradle",
    "build.gradle.kts",
    "pubspec.yaml",
}
_MAX_PROJECTS = 100
_MAX_FILES_PER_PROJECT = 2000
_MAX_SOURCE_FILES_RETURNED = 200
_MAX_PREVIEW_BYTES = 16 * 1024
_MAX_PREVIEW_CHARACTERS = 1200
_MAX_RECONSTRUCTION_SAMPLE_BYTES = 256 * 1024 * 1024
_MAX_EQUIVALENCE_SEMANTIC_IR_BYTES = 16 * 1024 * 1024


def reconstruct_source_project(
    sample: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    analysis: Mapping[str, Any] | None = None,
    *,
    strategy: str = "auto",
    semantic_ir: Mapping[str, Any] | None = None,
    gui_analysis: Mapping[str, Any] | None = None,
    engine_analysis: Mapping[str, Any] | None = None,
    android_analysis: Mapping[str, Any] | None = None,
    protocol_analysis: Mapping[str, Any] | None = None,
    dynamic_analysis: Any = None,
    static_analysis: Mapping[str, Any] | None = None,
    validate: bool = False,
    validation_options: Mapping[str, Any] | None = None,
    runtime_validation_spec: Mapping[str, Any] | str | os.PathLike[str] | None = None,
    behavior_validation_spec: Mapping[str, Any] | str | os.PathLike[str] | None = None,
    behavior_original_dir: str | os.PathLike[str] | None = None,
    **extra_evidence: Any,
) -> dict[str, Any]:
    """Generate a provenance-backed, editable source project skeleton.

    ``analysis`` accepts the aggregate analyzer payload used by the existing
    reconstruction pipeline.  Individual evidence arguments override matching
    values in that payload, which also makes the function useful to focused
    tools and tests.  The sample is read in bounded chunks and never opened for
    writing.  Validation is opt-in for direct callers so source generation
    itself never requires an external toolchain; production entry points can
    enable it explicitly after generation.
    """

    if not isinstance(validate, bool):
        raise TypeError("validate must be a boolean")
    normalized_runtime_spec = _load_runtime_validation_spec(runtime_validation_spec)
    normalized_behavior_spec = _load_behavior_validation_spec(behavior_validation_spec)
    static_override: Any = static_analysis
    if extra_evidence:
        if static_analysis is not None and not isinstance(static_analysis, Mapping):
            raise TypeError("static_analysis must be a mapping when extra evidence is supplied")
        static_override = {**dict(static_analysis or {}), **extra_evidence}

    overrides = {
        "semantic_ir": semantic_ir,
        "gui_analysis": gui_analysis,
        "engine_analysis": engine_analysis,
        "android_analysis": android_analysis,
        "protocol_analysis": protocol_analysis,
        "dynamic_analysis": dynamic_analysis,
        "static_analysis": static_override,
    }
    result = _generate_source_project(
        sample,
        out_dir,
        analysis,
        strategy=strategy,
        evidence_overrides=overrides,
        max_sample_bytes=_MAX_RECONSTRUCTION_SAMPLE_BYTES,
    )
    if validate:
        attach_source_validation(result, validation_options=validation_options)
    if normalized_runtime_spec is not None:
        attach_source_runtime_validation(result, normalized_runtime_spec)
    if normalized_behavior_spec is not None:
        original_dir = (
            Path(behavior_original_dir).expanduser()
            if behavior_original_dir is not None
            else _default_behavior_original_dir(sample)
        )
        attach_source_behavior_validation(result, original_dir, normalized_behavior_spec)
    attach_source_equivalence_assessment(result)
    return result


def attach_source_behavior_validation(
    result: Any,
    original_dir: str | os.PathLike[str],
    validation_spec: Mapping[str, Any] | str | os.PathLike[str],
) -> Any:
    """Run and persist an original-versus-reconstruction behavior comparison."""

    payload = getattr(result, "data", None)
    if not isinstance(payload, dict):
        payload = result if isinstance(result, dict) else None
    if not isinstance(payload, dict):
        return result

    project_value = payload.get("project_dir")
    if not isinstance(project_value, (str, os.PathLike)):
        return result
    project_dir = Path(project_value).expanduser()
    if project_dir.is_symlink() or not project_dir.is_dir():
        return result

    normalized_spec = _load_behavior_validation_spec(validation_spec)
    if normalized_spec is None:
        raise TypeError("validation_spec must be a mapping or JSON file path")
    project_dir = project_dir.resolve(strict=True)
    validation_result = validate_source_behavior(
        original_dir,
        project_dir,
        normalized_spec,
    )
    if not isinstance(validation_result, Mapping):
        raise TypeError("behavior validator must return a mapping")
    validation = dict(validation_result)
    status = validation.get("status")
    if status not in {"passed", "failed", "unavailable"}:
        raise ValueError(f"behavior validator returned an invalid status: {status!r}")
    behavior_equivalent = status == "passed" and validation.get("behavior_equivalent") is True
    provenance_value = validation.get("provenance")
    provenance = dict(provenance_value) if isinstance(provenance_value, Mapping) else {}
    artifact_name = DEFAULT_BEHAVIOR_VALIDATION_PATH
    validation_artifact_value = validation.get("artifact")
    validation_artifact = (
        dict(validation_artifact_value)
        if isinstance(validation_artifact_value, Mapping)
        else {}
    )
    validation_artifact.update(
        {
            "name": artifact_name,
            "kind": "source_behavior_validation",
            "role": "behavioral_equivalence_evidence",
            "media_type": "application/json",
            "status": status,
            "provenance": provenance,
            "behavior_equivalent": behavior_equivalent,
        }
    )
    validation["status"] = status
    validation["provenance"] = provenance
    validation["artifact"] = validation_artifact
    validation["behavior_equivalent"] = behavior_equivalent

    report_path, report_sha256 = _write_source_behavior_validation_report(
        project_dir,
        validation,
    )
    artifact = dict(validation_artifact)
    artifact.update({"path": str(report_path), "sha256": report_sha256})

    existing_artifacts = payload.get("artifacts")
    artifacts = list(existing_artifacts) if isinstance(existing_artifacts, list) else []
    payload["artifacts"] = [
        item
        for item in artifacts
        if not _matches_source_behavior_artifact(
            item,
            artifact_name,
            report_path,
            project_dir,
        )
    ]
    payload["artifacts"].append(artifact)

    report_text = str(report_path)
    existing_files = payload.get("generated_files")
    generated_files = list(existing_files) if isinstance(existing_files, list) else []
    generated_files = [
        item
        for item in generated_files
        if not _same_resolved_path(item, report_path, relative_to=project_dir)
    ]
    generated_files.append(report_text)
    payload["generated_files"] = generated_files

    manifest_entries = payload.get("evidence_manifest_entries")
    entries = list(manifest_entries) if isinstance(manifest_entries, list) else []
    entries = [
        item
        for item in entries
        if not _matches_source_behavior_artifact(
            item,
            artifact_name,
            report_path,
            project_dir,
        )
    ]
    entries.append(
        {
            "name": artifact_name,
            "path": report_text,
            "kind": "source_behavior_validation",
            "role": "behavioral_equivalence_evidence",
            "media_type": "application/json",
            "status": status,
            "sha256": report_sha256,
            "evidence_sha256": artifact.get("evidence_sha256"),
            "provenance": provenance,
            "behavior_equivalent": behavior_equivalent,
        }
    )
    payload["evidence_manifest_entries"] = entries
    payload["behavior_validation"] = validation
    payload["behavior_validation_status"] = status
    payload["behavior_validation_provenance"] = provenance
    payload["behavior_validation_artifact"] = report_text
    payload["behavior_equivalent"] = behavior_equivalent
    attach_source_equivalence_assessment(payload)
    return result


def attach_source_runtime_validation(
    result: Any,
    validation_spec: Mapping[str, Any] | str | os.PathLike[str],
) -> Any:
    """Execute and persist an explicit runtime validation specification."""

    payload = getattr(result, "data", None)
    if not isinstance(payload, dict):
        payload = result if isinstance(result, dict) else None
    if not isinstance(payload, dict):
        return result

    project_value = payload.get("project_dir")
    if not isinstance(project_value, (str, os.PathLike)):
        return result
    project_dir = Path(project_value).expanduser()
    if project_dir.is_symlink() or not project_dir.is_dir():
        return result

    normalized_spec = _load_runtime_validation_spec(validation_spec)
    if normalized_spec is None:
        raise TypeError("validation_spec must be a mapping or JSON file path")
    project_dir = project_dir.resolve(strict=True)
    validation_result = validate_source_runtime(project_dir, normalized_spec)
    if not isinstance(validation_result, Mapping):
        raise TypeError("runtime validator must return a mapping")
    validation = dict(validation_result)
    status = validation.get("status")
    if status not in {"passed", "failed", "unavailable"}:
        raise ValueError(f"runtime validator returned an invalid status: {status!r}")
    confidence = validation.get("confidence")
    confidence_score = confidence.get("score") if isinstance(confidence, Mapping) else None
    provenance_value = validation.get("provenance")
    provenance = dict(provenance_value) if isinstance(provenance_value, Mapping) else {}
    artifact_name = DEFAULT_RUNTIME_VALIDATION_PATH
    validation_artifact_value = validation.get("artifact")
    validation_artifact = (
        dict(validation_artifact_value)
        if isinstance(validation_artifact_value, Mapping)
        else {}
    )
    validation_artifact.update(
        {
            "name": artifact_name,
            "kind": "source_runtime_validation",
            "role": "validation_evidence",
            "media_type": "application/json",
            "status": status,
            "confidence": confidence_score,
            "provenance": provenance,
            "behavior_equivalent": False,
        }
    )
    validation["status"] = status
    validation["provenance"] = provenance
    validation["artifact"] = validation_artifact
    validation["behavior_equivalent"] = False

    report_path, report_sha256 = _write_source_runtime_validation_report(
        project_dir,
        validation,
    )
    artifact = dict(validation_artifact)
    artifact.update(
        {
            "path": str(report_path),
            "sha256": report_sha256,
        }
    )

    existing_artifacts = payload.get("artifacts")
    artifacts = list(existing_artifacts) if isinstance(existing_artifacts, list) else []
    payload["artifacts"] = [
        item
        for item in artifacts
        if not _matches_source_runtime_artifact(
            item,
            artifact_name,
            report_path,
            project_dir,
        )
    ]
    payload["artifacts"].append(artifact)

    report_text = str(report_path)
    existing_files = payload.get("generated_files")
    generated_files = list(existing_files) if isinstance(existing_files, list) else []
    generated_files = [
        item
        for item in generated_files
        if not _same_resolved_path(item, report_path, relative_to=project_dir)
    ]
    generated_files.append(report_text)
    payload["generated_files"] = generated_files

    manifest_entries = payload.get("evidence_manifest_entries")
    entries = list(manifest_entries) if isinstance(manifest_entries, list) else []
    entries = [
        item
        for item in entries
        if not _matches_source_runtime_artifact(
            item,
            artifact_name,
            report_path,
            project_dir,
        )
    ]
    entries.append(
        {
            "name": artifact_name,
            "path": report_text,
            "kind": "source_runtime_validation",
            "role": "validation_evidence",
            "media_type": "application/json",
            "status": status,
            "confidence": confidence_score,
            "sha256": report_sha256,
            "evidence_sha256": artifact.get("evidence_sha256"),
            "provenance": provenance,
            "behavior_equivalent": False,
        }
    )
    payload["evidence_manifest_entries"] = entries
    payload["runtime_validation"] = validation
    payload["runtime_validation_status"] = status
    payload["runtime_validation_confidence"] = confidence
    payload["runtime_validation_provenance"] = provenance
    payload["runtime_validation_artifact"] = report_text
    payload["behavior_equivalent"] = False
    attach_source_equivalence_assessment(payload)
    return result


def _write_source_runtime_validation_report(
    project_dir: Path,
    validation: Mapping[str, Any],
) -> tuple[Path, str]:
    return _write_source_validation_report(
        project_dir,
        validation,
        DEFAULT_RUNTIME_VALIDATION_PATH,
        "runtime validation",
    )


def _write_source_behavior_validation_report(
    project_dir: Path,
    validation: Mapping[str, Any],
) -> tuple[Path, str]:
    return _write_source_validation_report(
        project_dir,
        validation,
        DEFAULT_BEHAVIOR_VALIDATION_PATH,
        "behavior validation",
    )


def _write_source_validation_report(
    project_dir: Path,
    validation: Mapping[str, Any],
    artifact_name: str,
    label: str,
) -> tuple[Path, str]:
    relative_path = PurePosixPath(artifact_name)
    if (
        relative_path.is_absolute()
        or not relative_path.parts
        or any(part in {"", ".", ".."} for part in relative_path.parts)
    ):
        raise ValueError(f"{label} artifact path must be project-relative")

    project_root = project_dir.resolve(strict=True)
    report_parent = project_root.joinpath(*relative_path.parts[:-1])
    report_parent.mkdir(parents=True, exist_ok=True)
    resolved_parent = report_parent.resolve(strict=True)
    try:
        resolved_parent.relative_to(project_root)
    except ValueError as error:
        raise ValueError(f"{label} artifact path escapes the source project") from error
    if resolved_parent != report_parent or not resolved_parent.is_dir():
        raise ValueError(f"{label} artifact path traverses a symbolic link")

    report_path = resolved_parent / relative_path.name
    if report_path.is_symlink() or (report_path.exists() and not report_path.is_file()):
        raise ValueError(f"{label} artifact path is not a regular file")

    serialized = (
        json.dumps(
            validation,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=resolved_parent,
        prefix=f".{relative_path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, report_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return report_path, hashlib.sha256(serialized).hexdigest()


def _matches_source_runtime_artifact(
    value: Any,
    artifact_name: str,
    report_path: Path,
    project_dir: Path,
) -> bool:
    if not isinstance(value, Mapping):
        return False
    if value.get("name") == artifact_name:
        return True
    return _same_resolved_path(
        value.get("path"),
        report_path,
        relative_to=project_dir,
    )


def _matches_source_behavior_artifact(
    value: Any,
    artifact_name: str,
    report_path: Path,
    project_dir: Path,
) -> bool:
    if not isinstance(value, Mapping):
        return False
    if value.get("name") == artifact_name:
        return True
    return _same_resolved_path(
        value.get("path"),
        report_path,
        relative_to=project_dir,
    )


def _matches_source_equivalence_artifact(
    value: Any,
    artifact_name: str,
    report_path: Path,
    project_dir: Path,
) -> bool:
    if not isinstance(value, Mapping):
        return False
    if value.get("name") == artifact_name:
        return True
    return _same_resolved_path(
        value.get("path"),
        report_path,
        relative_to=project_dir,
    )


def _same_resolved_path(
    value: Any,
    expected: Path,
    *,
    relative_to: Path | None = None,
) -> bool:
    if not isinstance(value, (str, os.PathLike)):
        return False
    try:
        path = Path(value).expanduser()
        if not path.is_absolute() and relative_to is not None:
            path = relative_to / path
        return path.resolve(strict=False) == expected
    except (OSError, RuntimeError, ValueError):
        return False


def _load_runtime_validation_spec(
    value: Mapping[str, Any] | str | os.PathLike[str] | None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, (str, os.PathLike)):
        path = Path(value).expanduser().resolve(strict=True)
        if not path.is_file():
            raise ValueError("runtime validation spec path must identify a JSON file")
        parsed = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(parsed, Mapping):
            raise ValueError("runtime validation spec root must be a JSON object")
        return dict(parsed)
    raise TypeError("runtime_validation_spec must be a mapping or JSON file path")


def _load_behavior_validation_spec(
    value: Mapping[str, Any] | str | os.PathLike[str] | None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, (str, os.PathLike)):
        path = Path(value).expanduser().resolve(strict=True)
        if not path.is_file():
            raise ValueError("behavior validation spec path must identify a JSON file")
        parsed = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(parsed, Mapping):
            raise ValueError("behavior validation spec root must be a JSON object")
        return dict(parsed)
    raise TypeError("behavior_validation_spec must be a mapping or JSON file path")


def _default_behavior_original_dir(sample: str | os.PathLike[str]) -> Path:
    path = Path(sample).expanduser().resolve(strict=True)
    return path if path.is_dir() else path.parent


def attach_source_validation(
    result: Any,
    *,
    validation_options: Mapping[str, Any] | None = None,
) -> Any:
    """Validate a successful reconstruction result and declare its report artifact.

    ``result`` may be either the generated payload or a ``ToolResult`` carrying
    that payload in ``data``.  Generation success remains independent from the
    validation status: unavailable local tools and compiler failures are
    recorded in the validation report without relabeling the generated files.
    """

    payload = getattr(result, "data", None)
    if not isinstance(payload, dict):
        payload = result if isinstance(result, dict) else None
    if not isinstance(payload, dict):
        return result

    project_value = payload.get("project_dir")
    if not isinstance(project_value, (str, os.PathLike)):
        return result
    project_dir = Path(project_value).expanduser()
    if not project_dir.is_dir():
        return result

    if validation_options is None:
        options: dict[str, Any] = {}
    elif isinstance(validation_options, Mapping):
        options = dict(validation_options)
    else:
        raise TypeError("validation_options must be a mapping")
    validation = validate_and_write_source_project(project_dir, **options)
    report_path = project_dir.resolve() / "source" / "validation.json"
    artifact_name = "source/validation.json"
    artifact = {
        "name": artifact_name,
        "path": str(report_path),
        "kind": "source_validation",
        "role": "validation_evidence",
        "status": validation["status"],
        "validation_level": validation["level"],
        "toolchain": validation["toolchain"],
        "validated_file_count": len(validation["validated_files"]),
        "placeholder_count": validation["placeholder_count"],
        "behavior_equivalent": False,
    }

    existing_artifacts = payload.get("artifacts")
    artifacts = list(existing_artifacts) if isinstance(existing_artifacts, list) else []
    payload["artifacts"] = [
        item
        for item in artifacts
        if not isinstance(item, Mapping) or item.get("name") != artifact_name
    ]
    payload["artifacts"].append(artifact)

    existing_files = payload.get("generated_files")
    generated_files = list(existing_files) if isinstance(existing_files, list) else []
    report_text = str(report_path)
    if report_text not in generated_files:
        generated_files.append(report_text)
    payload["generated_files"] = generated_files

    manifest_entries = payload.get("evidence_manifest_entries")
    entries = list(manifest_entries) if isinstance(manifest_entries, list) else []
    entries = [
        item
        for item in entries
        if not isinstance(item, Mapping) or item.get("path") != report_text
    ]
    entries.append(
        {
            "path": report_text,
            "kind": "json",
            "role": "validation_evidence",
            "status": validation["status"],
        }
    )
    payload["evidence_manifest_entries"] = entries
    payload["validation"] = validation
    payload["validation_status"] = validation["status"]
    payload["validation_level"] = validation["level"]
    payload["validation_toolchain"] = validation["toolchain"]
    payload["validated_file_count"] = len(validation["validated_files"])
    payload["placeholder_count"] = validation["placeholder_count"]
    payload["behavior_equivalent"] = False
    payload["validation_artifact"] = report_text
    attach_source_equivalence_assessment(payload)
    return result


def attach_source_equivalence_assessment(result: Any) -> Any:
    """Assess collected reconstruction evidence and persist the bounded claim."""

    payload = getattr(result, "data", None)
    if not isinstance(payload, dict):
        payload = result if isinstance(result, dict) else None
    if not isinstance(payload, dict):
        return result

    project_value = payload.get("project_dir")
    if not isinstance(project_value, (str, os.PathLike)):
        return result
    project_dir = Path(project_value).expanduser()
    if project_dir.is_symlink() or not project_dir.is_dir():
        return result
    project_dir = project_dir.resolve(strict=True)

    evidence = dict(payload)
    semantic_ir = payload.get("semantic_ir")
    if not isinstance(semantic_ir, Mapping):
        semantic_ir = _load_equivalence_semantic_ir(project_dir)
    if isinstance(semantic_ir, Mapping):
        evidence["semantic_ir"] = semantic_ir
    assessment = assess_source_equivalence(evidence)

    artifact_name = DEFAULT_EQUIVALENCE_ASSESSMENT_PATH
    report_path, report_sha256 = _write_source_validation_report(
        project_dir,
        assessment,
        artifact_name,
        "equivalence assessment",
    )
    report_text = str(report_path)
    status = str(assessment.get("status") or "unverified")
    observed_evidence_matched = assessment.get("observed_evidence_matched") is True
    artifact = {
        "name": artifact_name,
        "path": report_text,
        "kind": "source_equivalence_assessment",
        "role": "evidence_assessment",
        "media_type": "application/json",
        "status": status,
        "score": assessment.get("score"),
        "observed_evidence_matched": observed_evidence_matched,
        "claim_scope": "observed_evidence_only",
        "complete_behavior_equivalence_proven": False,
        "sha256": report_sha256,
    }

    existing_artifacts = payload.get("artifacts")
    artifacts = list(existing_artifacts) if isinstance(existing_artifacts, list) else []
    payload["artifacts"] = [
        item
        for item in artifacts
        if not _matches_source_equivalence_artifact(
            item,
            artifact_name,
            report_path,
            project_dir,
        )
    ]
    payload["artifacts"].append(dict(artifact))

    existing_files = payload.get("generated_files")
    generated_files = list(existing_files) if isinstance(existing_files, list) else []
    payload["generated_files"] = [
        item
        for item in generated_files
        if not _same_resolved_path(item, report_path, relative_to=project_dir)
    ]
    payload["generated_files"].append(report_text)

    manifest_entries = payload.get("evidence_manifest_entries")
    entries = list(manifest_entries) if isinstance(manifest_entries, list) else []
    entries = [
        item
        for item in entries
        if not _matches_source_equivalence_artifact(
            item,
            artifact_name,
            report_path,
            project_dir,
        )
    ]
    entries.append(dict(artifact))
    payload["evidence_manifest_entries"] = entries

    dimensions = assessment.get("dimensions")
    dimension_statuses = {
        str(name): str(value.get("status") or "unverified")
        for name, value in dimensions.items()
        if isinstance(value, Mapping)
    } if isinstance(dimensions, Mapping) else {}
    payload["equivalence_assessment"] = assessment
    payload["equivalence_assessment_status"] = status
    payload["equivalence_assessment_score"] = assessment.get("score")
    payload["observed_evidence_matched"] = observed_evidence_matched
    payload["equivalence_dimension_statuses"] = dimension_statuses
    payload["equivalence_mismatch_count"] = _as_int(assessment.get("mismatch_count"))
    payload["claim_scope"] = "observed_evidence_only"
    payload["complete_behavior_equivalence_proven"] = False
    payload["equivalence_assessment_artifact"] = report_text
    return result


def _load_equivalence_semantic_ir(project_dir: Path) -> Mapping[str, Any] | None:
    analysis_dir = project_dir / "analysis"
    candidate = analysis_dir / "semantic_ir.json"
    if analysis_dir.is_symlink() or candidate.is_symlink() or not candidate.is_file():
        return None
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(project_dir)
        if resolved.stat().st_size > _MAX_EQUIVALENCE_SEMANTIC_IR_BYTES:
            return None
        with resolved.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return value if isinstance(value, Mapping) else None


# Compatibility names used by older integrations and capability dispatchers.
generate_source_reconstruction = reconstruct_source_project
reconstruct_project = reconstruct_source_project
reconstruct_source = reconstruct_source_project


def summarize_source_reconstruction(
    workspace: str | Path,
    *,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return JSON-serializable source-reconstruction data below ``workspace``.

    A project is discovered by the directory names emitted by the built-in C
    and GUI reconstructors: ``reconstructed_*`` and ``reconstructed_gui``.
    Project and source-file paths are relative to the workspace/project.
    Invalid optional JSON metadata is recorded as a diagnostic and never
    prevents other projects from reaching the dashboard.
    """

    root = Path(workspace).expanduser()
    state = diagnostics if diagnostics is not None else {}
    _initialize_diagnostics(state)
    summary = {
        "project_total": 0,
        "source_file_total": 0,
        "resource_file_total": 0,
        "function_total": 0,
        "dynamic_evidence_total": 0,
        "semantic_entity_total": 0,
        "semantic_capability_total": 0,
        "verified_project_total": 0,
        "validation_project_total": 0,
        "validation_passed_total": 0,
        "validation_failed_total": 0,
        "validation_unavailable_total": 0,
        "behavior_validation_project_total": 0,
        "behavior_equivalent_project_total": 0,
        "behavior_validation_status_counts": {
            "failed": 0,
            "passed": 0,
            "unavailable": 0,
        },
        "equivalence_assessment_project_total": 0,
        "observed_evidence_matched_project_total": 0,
        "equivalence_assessment_status_counts": {
            "matched": 0,
            "mismatch": 0,
            "unavailable": 0,
            "unverified": 0,
        },
        "validated_file_total": 0,
        "placeholder_total": 0,
        "validation_status_counts": {
            "failed": 0,
            "passed": 0,
            "unavailable": 0,
        },
        "language_counts": {},
        "output_stack_counts": {},
    }
    if not root.is_dir():
        state["workspace_unavailable"] = str(root)
        return {"summary": summary, "projects": [], "diagnostics": state}

    root = root.resolve()
    projects = [_summarize_project(root, path, state) for path in _project_directories(root, state)]
    projects.sort(key=lambda item: (str(item.get("relative_path") or ""), str(item.get("name") or "")))

    language_counts: dict[str, int] = {}
    output_stack_counts: dict[str, int] = {}
    for project in projects:
        summary["source_file_total"] += _as_int(project.get("source_file_count"))
        summary["resource_file_total"] += _as_int(project.get("resource_file_count"))
        summary["function_total"] += _as_int(project.get("function_count"))
        summary["dynamic_evidence_total"] += _as_int(project.get("dynamic_evidence_count"))
        summary["semantic_entity_total"] += _as_int(project.get("semantic_entity_count"))
        summary["semantic_capability_total"] += _as_int(project.get("semantic_capability_count"))
        if project.get("verification_score") is not None:
            summary["verified_project_total"] += 1
        if project.get("validation") is not None:
            summary["validation_project_total"] += 1
            summary["validated_file_total"] += _as_int(project.get("validated_file_count"))
            summary["placeholder_total"] += _as_int(project.get("placeholder_count"))
            validation_status = project.get("validation_status")
            if validation_status in {"failed", "passed", "unavailable"}:
                summary["validation_status_counts"][validation_status] += 1
                summary[f"validation_{validation_status}_total"] += 1
        behavior_status = project.get("behavior_validation_status")
        if behavior_status in {"failed", "passed", "unavailable"}:
            summary["behavior_validation_project_total"] += 1
            summary["behavior_validation_status_counts"][behavior_status] += 1
        if project.get("behavior_equivalent") is True:
            summary["behavior_equivalent_project_total"] += 1
        equivalence_assessment = project.get("equivalence_assessment")
        if isinstance(equivalence_assessment, Mapping):
            summary["equivalence_assessment_project_total"] += 1
            assessment_status = project.get("equivalence_assessment_status")
            if assessment_status in summary["equivalence_assessment_status_counts"]:
                summary["equivalence_assessment_status_counts"][assessment_status] += 1
            if project.get("observed_evidence_matched") is True:
                summary["observed_evidence_matched_project_total"] += 1
        _increment(language_counts, project.get("language"))
        _increment(output_stack_counts, project.get("output_stack"))
    summary["project_total"] = len(projects)
    summary["language_counts"] = dict(sorted(language_counts.items()))
    summary["output_stack_counts"] = dict(sorted(output_stack_counts.items()))
    return {"summary": summary, "projects": projects, "diagnostics": state}


def _initialize_diagnostics(diagnostics: dict[str, Any]) -> None:
    diagnostics.setdefault("directories_scanned", 0)
    diagnostics.setdefault("projects_discovered", 0)
    diagnostics.setdefault("metadata_files_loaded", 0)
    diagnostics.setdefault("malformed_metadata", 0)
    diagnostics.setdefault("skipped_files", [])
    diagnostics.setdefault("truncated_projects", 0)
    diagnostics.setdefault("truncated_file_lists", 0)


def _project_directories(root: Path, diagnostics: dict[str, Any]) -> Iterable[Path]:
    """Yield reconstruction project roots while pruning non-artifact trees."""

    found = 0
    for current_root, directory_names, _ in os.walk(root, topdown=True):
        diagnostics["directories_scanned"] += 1
        directory_names[:] = sorted(
            name for name in directory_names if name.lower() not in _IGNORED_DIRECTORIES
        )
        candidates = [name for name in directory_names if _is_project_directory(name)]
        for name in candidates:
            if found >= _MAX_PROJECTS:
                diagnostics["truncated_projects"] += 1
                return
            candidate = Path(current_root) / name
            if not _is_within(root, candidate):
                diagnostics["skipped_files"].append({"path": str(candidate), "reason": "outside workspace"})
                directory_names.remove(name)
                continue
            found += 1
            diagnostics["projects_discovered"] += 1
            directory_names.remove(name)
            yield candidate


def _is_project_directory(name: str) -> bool:
    normalized = name.lower()
    return normalized == "reconstructed_gui" or normalized.startswith("reconstructed_")


def _summarize_project(root: Path, project_dir: Path, diagnostics: dict[str, Any]) -> dict[str, Any]:
    project_dir = project_dir.resolve()
    metadata = _load_project_metadata(project_dir, diagnostics)
    (
        source_files,
        source_file_count,
        source_languages,
        resource_file_count,
        entrypoints,
        file_scan_truncated,
    ) = _collect_project_files(project_dir, diagnostics)
    summary_data = _mapping(metadata.get("summary"))
    reconstruction_plan = _mapping(metadata.get("reconstruction_plan"))
    module_map = _mapping(metadata.get("module_map"))
    gui_strategy = _mapping(metadata.get("gui_strategy"))
    gui_analysis = _mapping(metadata.get("gui_analysis"))
    semantic_ir = _mapping(metadata.get("semantic_ir"))
    semantic_summary = _mapping(semantic_ir.get("summary"))
    source_reconstruction = _mapping(metadata.get("source_reconstruction"))
    source_evidence = _mapping(source_reconstruction.get("evidence"))
    source_semantic_summary = _mapping(source_evidence.get("semantic_ir"))
    source_dynamic_summary = _mapping(source_evidence.get("dynamic_analysis"))
    project_metadata = _mapping(metadata.get("project"))
    provenance = _mapping(metadata.get("provenance"))
    confidence = _mapping(metadata.get("confidence"))
    evidence_index = _mapping(metadata.get("evidence_index"))
    behavior_hints = _mapping(metadata.get("behavior_hints"))
    validation = _summarize_validation(metadata.get("validation"))
    behavior_validation = _mapping(metadata.get("behavior_validation"))
    behavior_validation_status = _first_text(behavior_validation.get("status"))
    behavior_equivalent = _behavior_validation_equivalent(behavior_validation)
    equivalence_assessment = _summarize_equivalence_assessment(
        metadata.get("equivalence_assessment")
    )
    equivalence_dimensions = _mapping(
        equivalence_assessment.get("dimensions") if equivalence_assessment else None
    )
    equivalence_dimension_statuses = {
        str(name): _first_text(value.get("status")) or "unverified"
        for name, value in equivalence_dimensions.items()
        if isinstance(value, Mapping)
    }
    verification = _mapping(metadata.get("reconstruction_verification"))
    verification_coverage = _mapping(verification.get("coverage"))
    dynamic_evidence = metadata.get("dynamic_evidence")

    gui_strategy_data = _mapping(gui_analysis.get("strategy"))
    output_stack = _first_text(
        project_metadata.get("output_stack"),
        project_metadata.get("stack"),
        source_reconstruction.get("selected_stack"),
        gui_strategy.get("output_stack"),
        gui_strategy_data.get("output_stack"),
        gui_strategy.get("framework"),
        gui_analysis.get("framework"),
    )
    language = (
        _first_text(project_metadata.get("language"), source_reconstruction.get("language"))
        or _dominant_language(source_languages)
        or _language_from_stack(output_stack)
        or _detect_project_language(project_dir)
    )
    modules = module_map.get("modules")
    module_count = len(modules) if isinstance(modules, Mapping) else _as_int(summary_data.get("module_count"))
    function_count = _as_int(summary_data.get("function_count"))
    if function_count == 0:
        function_count = sum(
            1
            for symbol in project_metadata.get("symbols") or []
            if isinstance(symbol, Mapping) and str(symbol.get("kind") or "").lower() in {"function", "method"}
        )
    dynamic_evidence_count = (
        len(dynamic_evidence)
        if isinstance(dynamic_evidence, list)
        else _as_int(summary_data.get("dynamic_evidence_count"))
    )
    if dynamic_evidence_count == 0:
        dynamic_evidence_count = _as_int(gui_analysis.get("dynamic_evidence_count"))
    if dynamic_evidence_count == 0:
        dynamic_evidence_count = _as_int(source_dynamic_summary.get("event_count"))

    semantic_entity_count = _as_int(semantic_summary.get("entity_count"))
    semantic_relation_count = _as_int(semantic_summary.get("relation_count"))
    semantic_capability_count = _as_int(semantic_summary.get("capability_count"))
    if semantic_entity_count == 0:
        semantic_entity_count = _as_int(source_semantic_summary.get("entity_count"))
    if semantic_relation_count == 0:
        semantic_relation_count = _as_int(source_semantic_summary.get("relation_count"))
    if semantic_capability_count == 0:
        semantic_capability_count = _as_int(source_semantic_summary.get("capability_count"))

    metadata_entrypoints = _relative_metadata_paths(project_metadata.get("entrypoints"))
    metadata_build_files = _relative_metadata_paths(project_metadata.get("build_files"))
    all_entrypoints = sorted(dict.fromkeys([*entrypoints, *metadata_entrypoints]))
    evidence_used = _text_items(project_metadata.get("evidence_used"))
    if not evidence_used:
        evidence_used = _text_items(evidence_index.get("present_sources"))
    artifacts = sorted(
        dict.fromkeys(
            [
                *_artifact_names(metadata.get("gui_analysis")),
                *_project_artifact_names(project_metadata),
                *(["source/validation.json"] if validation else []),
                *(
                    [DEFAULT_BEHAVIOR_VALIDATION_PATH]
                    if behavior_validation
                    else []
                ),
                *(
                    [DEFAULT_EQUIVALENCE_ASSESSMENT_PATH]
                    if equivalence_assessment
                    else []
                ),
            ]
        )
    )[:200]
    status = _first_text(
        source_reconstruction.get("status"),
        gui_strategy.get("status"),
        gui_analysis.get("status"),
        summary_data.get("status"),
    ) or "discovered"
    return {
        "name": project_dir.name,
        "relative_path": _relative_path(root, project_dir),
        "status": status,
        "language": language,
        "output_stack": output_stack,
        "readme_present": (project_dir / "README.md").is_file(),
        "source_file_count": source_file_count,
        "resource_file_count": resource_file_count,
        "function_count": function_count,
        "import_count": _as_int(summary_data.get("import_count")),
        "module_count": module_count,
        "dynamic_evidence_count": dynamic_evidence_count,
        "semantic_entity_count": semantic_entity_count,
        "semantic_relation_count": semantic_relation_count,
        "semantic_capability_count": semantic_capability_count,
        "verification_status": _first_text(verification.get("status")),
        "verification_score": _number_or_none(verification.get("score")),
        "validation": validation,
        "validation_status": validation.get("status") if validation else None,
        "validation_level": validation.get("level") if validation else None,
        "validation_toolchain": validation.get("toolchain") if validation else None,
        "validation_exit_code": validation.get("exit_code") if validation else None,
        "validated_file_count": len(validation.get("validated_files", [])) if validation else 0,
        "placeholder_count": _as_int(validation.get("placeholder_count")) if validation else 0,
        "behavior_validation": behavior_validation or None,
        "behavior_validation_status": behavior_validation_status,
        "behavior_validation_summary": _mapping(behavior_validation.get("summary")),
        "behavior_equivalent": (
            behavior_equivalent
            if behavior_validation
            else (False if validation else None)
        ),
        "equivalence_assessment": equivalence_assessment,
        "equivalence_assessment_status": (
            equivalence_assessment.get("status") if equivalence_assessment else None
        ),
        "equivalence_assessment_score": (
            equivalence_assessment.get("score") if equivalence_assessment else None
        ),
        "observed_evidence_matched": (
            equivalence_assessment.get("observed_evidence_matched") is True
            if equivalence_assessment
            else False
        ),
        "equivalence_dimension_statuses": equivalence_dimension_statuses,
        "equivalence_mismatch_count": (
            _as_int(equivalence_assessment.get("mismatch_count"))
            if equivalence_assessment
            else 0
        ),
        "claim_scope": (
            equivalence_assessment.get("claim_scope")
            if equivalence_assessment
            else None
        ),
        "complete_behavior_equivalence_proven": False,
        "semantic_coverage": _number_or_none(verification_coverage.get("semantic_coverage")),
        "module_coverage": _number_or_none(verification_coverage.get("module_coverage")),
        "next_task": _next_task(reconstruction_plan),
        "entrypoints": all_entrypoints,
        "build_files": metadata_build_files,
        "source_files": source_files,
        "source_files_truncated": file_scan_truncated or source_file_count > len(source_files),
        "stub_only": _first_bool(
            project_metadata.get("placeholder"),
            gui_strategy.get("stub_only"),
            summary_data.get("stub_only"),
        ),
        "confidence": _number_or_none(confidence.get("score")),
        "confidence_level": _first_text(confidence.get("level"), project_metadata.get("confidence_level")),
        "evidence_used": evidence_used,
        "evidence_source_count": len(evidence_used),
        "behavior_hint_count": _as_int(evidence_index.get("behavior_hint_count"))
        or sum(len(value) for value in behavior_hints.values() if isinstance(value, list)),
        "analysis_files": _relative_metadata_paths(project_metadata.get("analysis_files")),
        "project_file_count": _as_int(project_metadata.get("file_count")),
        "provenance": _summarize_provenance(provenance),
        "artifacts": artifacts,
    }


def _load_project_metadata(project_dir: Path, diagnostics: dict[str, Any]) -> dict[str, Any]:
    analysis_dir = project_dir / "analysis"
    filenames = {
        "summary": "summary.json",
        "source_reconstruction": "source_reconstruction.json",
        "project": "project.json",
        "provenance": "provenance.json",
        "confidence": "confidence.json",
        "evidence_index": "evidence_index.json",
        "behavior_hints": "behavior_hints.json",
        "reconstruction_plan": "reconstruction_plan.json",
        "module_map": "module_map.json",
        "dynamic_evidence": "dynamic_evidence.json",
        "gui_strategy": "gui_strategy.json",
        "gui_analysis": "gui_analysis.json",
        "semantic_ir": "semantic_ir.json",
        "reconstruction_verification": "reconstruction_verification.json",
        "equivalence_assessment": "equivalence_assessment.json",
    }
    result: dict[str, Any] = {}
    for key, filename in filenames.items():
        value = _load_json(analysis_dir / filename, diagnostics)
        if value is not None:
            result[key] = value
    validation = _load_json(project_dir / "source" / "validation.json", diagnostics)
    if validation is not None:
        result["validation"] = validation
    behavior_validation = _load_json(
        project_dir.joinpath(*PurePosixPath(DEFAULT_BEHAVIOR_VALIDATION_PATH).parts),
        diagnostics,
    )
    if behavior_validation is not None:
        result["behavior_validation"] = behavior_validation
    return result


def _load_json(path: Path, diagnostics: dict[str, Any]) -> Any:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        diagnostics["malformed_metadata"] += 1
        diagnostics["skipped_files"].append({"path": str(path), "reason": str(error)})
        return None
    diagnostics["metadata_files_loaded"] += 1
    return value


def _collect_project_files(
    project_dir: Path, diagnostics: dict[str, Any]
) -> tuple[list[dict[str, Any]], int, dict[str, int], int, list[str], bool]:
    source_files: list[dict[str, Any]] = []
    source_file_count = 0
    source_languages: dict[str, int] = {}
    resource_file_count = 0
    entrypoints: list[str] = []
    scanned_files = 0
    for current_root, directory_names, filenames in os.walk(project_dir, topdown=True):
        directory_names[:] = sorted(
            (name for name in directory_names if name.lower() not in _IGNORED_DIRECTORIES),
            key=lambda name: (name.lower() not in _SOURCE_PRIORITY_DIRECTORIES, name.lower()),
        )
        for filename in sorted(filenames):
            scanned_files += 1
            if scanned_files > _MAX_FILES_PER_PROJECT:
                diagnostics["truncated_file_lists"] += 1
                return source_files, source_file_count, source_languages, resource_file_count, entrypoints, True
            path = Path(current_root) / filename
            if not _is_within(project_dir, path):
                diagnostics["skipped_files"].append({"path": str(path), "reason": "outside project"})
                continue
            suffix = path.suffix.lower()
            relative = path.relative_to(project_dir).as_posix()
            lower_name = path.name.lower()
            if suffix in _RESOURCE_SUFFIXES:
                resource_file_count += 1
            if lower_name in _ENTRYPOINT_NAMES or lower_name in _BUILD_ENTRYPOINT_NAMES:
                entrypoints.append(relative)
            language = _SOURCE_LANGUAGES.get(suffix)
            if language is None:
                continue
            source_file_count += 1
            source_languages[language] = source_languages.get(language, 0) + 1
            if len(source_files) < _MAX_SOURCE_FILES_RETURNED:
                source_files.append(
                    {
                        "path": relative,
                        "language": language,
                        "size_bytes": _file_size(path),
                        "preview": _text_preview(path),
                    }
                )
    return source_files, source_file_count, source_languages, resource_file_count, entrypoints, False


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _text_preview(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            content = handle.read(_MAX_PREVIEW_BYTES)
    except OSError:
        return None
    if not content or b"\x00" in content:
        return None
    text = content.decode("utf-8", errors="replace").strip()
    return text[:_MAX_PREVIEW_CHARACTERS] if text else None


def _next_task(plan: Mapping[str, Any]) -> str | None:
    tasks = plan.get("tasks")
    if not isinstance(tasks, list):
        return None
    for task in tasks:
        if isinstance(task, Mapping):
            value = _first_text(task.get("name"), task.get("id"), task.get("description"))
            if value:
                return value
    return None


def _artifact_names(value: Any) -> list[str]:
    data = _mapping(value)
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list):
        return []
    names: list[str] = []
    for item in artifacts:
        if isinstance(item, Mapping):
            name = _first_text(item.get("name"), item.get("path"))
            if name:
                names.append(name)
    return names[:50]


def _project_artifact_names(value: Mapping[str, Any]) -> list[str]:
    files = value.get("files")
    if not isinstance(files, list):
        return []
    names = []
    for item in files:
        if not isinstance(item, Mapping):
            continue
        names.extend(_relative_metadata_paths([item.get("path")]))
        if len(names) >= 200:
            break
    return names[:200]


def _relative_metadata_paths(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        normalized = item.strip().replace("\\", "/")
        parts = [part for part in normalized.split("/") if part not in {"", "."}]
        if not parts or ".." in parts or ":" in parts[0] or normalized.startswith("/"):
            continue
        result.append("/".join(parts))
    return list(dict.fromkeys(result))[:200]


def _text_items(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return list(dict.fromkeys(str(item).strip() for item in value if isinstance(item, str) and item.strip()))[:50]


def _summarize_provenance(value: Mapping[str, Any]) -> dict[str, Any] | None:
    if not value:
        return None
    generator = _mapping(value.get("generator"))
    sample = _mapping(value.get("sample"))
    inputs = []
    raw_inputs = value.get("inputs")
    if isinstance(raw_inputs, list):
        for item in raw_inputs[:50]:
            if not isinstance(item, Mapping):
                continue
            inputs.append(
                {
                    "name": _first_text(item.get("name")),
                    "present": bool(item.get("present")),
                    "confidence": _number_or_none(item.get("confidence")),
                    "consumed_paths": _text_items(item.get("consumed_paths")),
                }
            )
    return {
        "generator": {
            "name": _first_text(generator.get("name")),
            "version": _first_text(generator.get("version")),
            "deterministic": _first_bool(generator.get("deterministic")),
        },
        "sample": {
            "name": _first_text(sample.get("name")),
            "sha256": _first_text(sample.get("sha256")),
            "size_bytes": _as_int(sample.get("size_bytes")),
        },
        "inputs": inputs,
    }


def _summarize_validation(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None

    status = value.get("status")
    if status not in {"failed", "passed", "unavailable"}:
        status = None
    level = value.get("level")
    if level not in {"build", "syntax"}:
        level = None
    toolchain = value.get("toolchain")
    if not isinstance(toolchain, str) or not toolchain.strip():
        toolchain = None
    exit_code = value.get("exit_code")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        exit_code = None
    command = value.get("command")
    if not isinstance(command, list):
        command = []
    diagnostics = value.get("diagnostics")
    if not isinstance(diagnostics, list):
        diagnostics = []
    provenance = value.get("provenance")
    if not isinstance(provenance, Mapping):
        provenance = {}

    return {
        "schema_version": _as_int(value.get("schema_version")) or 1,
        "status": status,
        "level": level,
        "toolchain": toolchain,
        "command": [item for item in command if isinstance(item, str)][:200],
        "exit_code": exit_code,
        "diagnostics": [item for item in diagnostics if isinstance(item, str)][:200],
        "validated_files": _relative_metadata_paths(value.get("validated_files")),
        "placeholder_count": _as_int(value.get("placeholder_count")),
        "behavior_equivalent": False,
        "provenance": dict(provenance),
    }


def _summarize_equivalence_assessment(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    status = _first_text(value.get("status"))
    if status not in {"matched", "mismatch", "unavailable", "unverified"}:
        status = "unverified"
    observed_evidence_matched = status == "matched" and _matched_assessment_contract(value)
    if status == "matched" and not observed_evidence_matched:
        status = "unverified"

    assessment = dict(value)
    assessment.update(
        {
            "status": status,
            "score": _unit_interval_number(value.get("score")),
            "observed_evidence_matched": observed_evidence_matched,
            "validated": False,
            "validated_within_observed_scope": observed_evidence_matched,
            "claim_scope": "observed_evidence_only",
            "complete_behavior_equivalence_proven": False,
            "perfect_equivalence_claimed": False,
            "mismatch_count": _as_int(value.get("mismatch_count")),
        }
    )
    return assessment


def _matched_assessment_contract(value: Mapping[str, Any]) -> bool:
    if (
        isinstance(value.get("schema_version"), bool)
        or value.get("schema_version") != EQUIVALENCE_ASSESSMENT_SCHEMA_VERSION
        or value.get("assessment_type") != "evidence_bounded_source_equivalence"
        or value.get("claim_scope") != "observed_evidence_only"
        or value.get("observed_evidence_matched") is not True
        or value.get("validated") is not False
        or value.get("validated_within_observed_scope") is not True
        or value.get("complete_behavior_equivalence_proven") is not False
        or value.get("perfect_equivalence_claimed") is not False
    ):
        return False

    mismatch_count = value.get("mismatch_count")
    mismatches = value.get("mismatches")
    if (
        not _zero_contract_count(mismatch_count)
        or not isinstance(mismatches, list)
        or mismatches
    ):
        return False

    reconstruction_form = value.get("reconstruction_form")
    if (
        not isinstance(reconstruction_form, Mapping)
        or reconstruction_form.get("status") != "recovered"
        or reconstruction_form.get("blocks_validation") is not False
        or not _zero_contract_count(reconstruction_form.get("placeholder_count"))
    ):
        return False

    required = value.get("required_dimensions")
    dimensions = value.get("dimensions")
    if (
        not isinstance(required, list)
        or not required
        or not isinstance(dimensions, Mapping)
        or any(not isinstance(name, str) for name in required)
        or len(set(required)) != len(required)
        or any(name not in EQUIVALENCE_DIMENSIONS for name in required)
        or any(name not in dimensions for name in EQUIVALENCE_DIMENSIONS)
        or not {
            "static_structure_coverage",
            "function_body_recovery",
            "compile_result",
        }.issubset(required)
    ):
        return False

    dimension_required = {
        name
        for name in EQUIVALENCE_DIMENSIONS
        if isinstance(dimensions.get(name), Mapping)
        and dimensions[name].get("required") is True
    }
    if dimension_required != set(required):
        return False

    for name in EQUIVALENCE_DIMENSIONS:
        if name in required:
            continue
        dimension = dimensions.get(name)
        provenance = dimension.get("provenance") if isinstance(dimension, Mapping) else None
        if (
            not isinstance(dimension, Mapping)
            or dimension.get("status") != "not_applicable"
            or dimension.get("required") is not False
            or not isinstance(provenance, list)
            or not provenance
            or any(not isinstance(item, str) or not item.strip() for item in provenance)
        ):
            return False

    thresholds = value.get("thresholds")
    overall_score = _unit_interval_number(value.get("score"))
    overall_threshold = (
        _unit_interval_number(thresholds.get("overall_score"))
        if isinstance(thresholds, Mapping)
        else None
    )
    if (
        overall_score is None
        or overall_threshold is None
        or overall_score < overall_threshold
    ):
        return False

    comparison_dimensions = {
        "runtime_differential_traces",
        "gui_matches",
        "protocol_matches",
        "behavior_matches",
    }
    for name in required:
        dimension = dimensions.get(name)
        if not isinstance(dimension, Mapping):
            return False
        score = _unit_interval_number(dimension.get("score"))
        threshold = _unit_interval_number(dimension.get("threshold"))
        provenance = dimension.get("provenance")
        if (
            dimension.get("status") != "matched"
            or dimension.get("required") is not True
            or score is None
            or threshold is None
            or score < threshold
            or dimension.get("meets_threshold") is not True
            or not isinstance(provenance, list)
            or not provenance
            or any(not isinstance(item, str) or not item.strip() for item in provenance)
            or not _positive_contract_count(dimension.get("matched_count"))
            or not _zero_contract_count(dimension.get("mismatched_count"))
        ):
            return False
        if name not in comparison_dimensions:
            continue
        observed_count = dimension.get("observed_count")
        minimum_count = dimension.get("minimum_evidence_count")
        if (
            not _positive_contract_count(observed_count)
            or not _positive_contract_count(minimum_count)
            or observed_count < minimum_count
            or dimension.get("matched_count") != observed_count
            or not _zero_contract_count(dimension.get("unverified_count"))
            or dimension.get("summary_consistent") is not True
            or not _zero_or_observed_contract_count(
                dimension.get("reported_total_count"), observed_count
            )
            or not _zero_or_observed_contract_count(
                dimension.get("reported_matched_count"), observed_count
            )
            or not _zero_contract_count(
                dimension.get("reported_mismatched_count")
            )
        ):
            return False
    return True


def _unit_interval_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if 0.0 <= number <= 1.0 else None


def _positive_contract_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _zero_contract_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == 0


def _zero_or_observed_contract_count(value: Any, observed_count: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value in {0, observed_count}
    )


def _behavior_validation_equivalent(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if value.get("status") != "passed" or value.get("behavior_equivalent") is not True:
        return False
    provenance = value.get("provenance")
    if not isinstance(provenance, Mapping):
        return False
    validator = provenance.get("validator")
    if not isinstance(validator, Mapping):
        return False
    return (
        validator.get("real_subprocess") is True
        and validator.get("runner_injected") is False
        and validator.get("shell") is False
    )


def _dominant_language(counts: Mapping[str, int]) -> str | None:
    if not counts:
        return None
    return sorted(counts, key=lambda item: (-counts[item], item))[0]


def _detect_project_language(project_dir: Path) -> str | None:
    if any(project_dir.glob("*.csproj")):
        return "csharp"
    if (project_dir / "package.json").is_file():
        return "javascript"
    if (project_dir / "pyproject.toml").is_file():
        return "python"
    if (project_dir / "CMakeLists.txt").is_file():
        return "c"
    return None


def _language_from_stack(stack: str | None) -> str | None:
    if not stack:
        return None
    normalized = stack.lower()
    if "wpf" in normalized or "winforms" in normalized or "c#" in normalized:
        return "csharp"
    if "pyside" in normalized or "python" in normalized:
        return "python"
    if "electron" in normalized or "react" in normalized:
        return "javascript"
    if "flutter" in normalized:
        return "dart"
    if "qt" in normalized or "win32" in normalized:
        return "c++"
    if "xcode" in normalized or "uikit" in normalized or "swift" in normalized:
        return "swift"
    if "android" in normalized:
        return "kotlin"
    return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _first_bool(*values: Any) -> bool | None:
    for value in values:
        if isinstance(value, bool):
            return value
    return None


def _as_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _number_or_none(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return round(float(value), 4)
    except (TypeError, ValueError):
        return None


def _increment(values: dict[str, int], value: Any) -> None:
    text = _first_text(value)
    if text:
        values[text] = values.get(text, 0) + 1


def _relative_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _is_within(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False
