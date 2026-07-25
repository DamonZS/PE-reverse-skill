"""Safe archive-to-workspace orchestration for mixed reverse-analysis targets."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

MAX_FILES = 20_000
MAX_FILE_SIZE = 1 << 30
MAX_TOTAL_SIZE = 4 << 30
TARGET_SUFFIXES = {".exe": "windows-executable", ".dll": "windows-library", ".apk": "android-package", ".ipa": "ios-package"}
MODEL_CONTEXT_FILE_LIMIT = 80
MODEL_CONTEXT_PREVIEW_LIMIT = 4000


def _target_kind(path: Path) -> tuple[str, bool, str]:
    """Classify executable containers by magic before consulting their suffix."""

    with path.open("rb") as stream:
        magic = stream.read(20)
    if magic.startswith(b"\x7fELF"):
        elf_type = int.from_bytes(magic[16:18], "little" if magic[5:6] == b"\x01" else "big") if len(magic) >= 18 else 0
        kind = "linux-native-library" if elf_type == 3 and path.suffix.casefold() == ".so" else "linux-native-executable"
        return kind, True, "elf_magic"
    suffix = path.suffix.casefold()
    return TARGET_SUFFIXES.get(suffix, "resource"), suffix in TARGET_SUFFIXES, "suffix"


def _capability_commands(source: Path, analysis_dir: Path) -> list[dict[str, Any]]:
    base = [sys.executable, "-m", "reverse_analyzer"]
    kind, _, detection = _target_kind(source)
    if kind.startswith("linux-native"):
        return [{
            "capability": "elf-binutils-source-reconstruction",
            "provider": "file+readelf+objdump+strings+native_reconstruct",
            "command": [sys.executable, "-m", "reverse_analyzer.native_reconstruct", str(source), "--out", str(analysis_dir)],
            "artifacts": ["native-evidence.json", "source/CMakeLists.txt", "source/project.json", "source/main.c"],
            "detection": detection,
        }]
    suffix = source.suffix.casefold()
    if suffix == ".exe":
        return [{
            "capability": "pe-static-decompile-gui-reconstruction",
            "provider": "ToolExecutor:analyze+ghidra+gui+semantic_ir+reconstruction_verify",
            "command": [*base, "analyze", str(source), "--out", str(analysis_dir), "--decompile", "--gui", "--reconstruct", "--reconstruct-gui"],
            "artifacts": ["report.json", "semantic-ir.json", "reconstruction-verification.json"],
        }]
    if suffix == ".dll":
        return [{
            "capability": "pe-library-static-decompile-reconstruction",
            "provider": "ToolExecutor:analyze+ghidra+semantic_ir+reconstruction_verify",
            "command": [*base, "analyze", str(source), "--out", str(analysis_dir), "--decompile", "--reconstruct"],
            "artifacts": ["report.json", "semantic-ir.json", "reconstruction-verification.json"],
        }]
    if suffix == ".apk":
        return [
            {
                "capability": "android-static-analysis",
                "provider": "ToolExecutor:android_analyze+semantic_ir",
                "command": [*base, "android", "analyze", str(source), "--out", str(analysis_dir)],
                "artifacts": ["android/analysis.json", "semantic-ir.json"],
            },
            {
                "capability": "android-java-kotlin-decompilation",
                "provider": "reverse_analyzer.tools.android:android_java_decompile (JADX)",
                "command": [*base, "android", "decompile", str(source), "--out", str(analysis_dir), "--destination", "source"],
                "artifacts": ["android/source", "android/java_decompilation.json"],
                "dependency": "jadx",
            },
            {
                "capability": "android-resource-smali-unpack",
                "provider": "CapabilityRegistry:android_rebuild (Apktool)",
                "command": [*base, "android", "unpack", str(source), "--out", str(analysis_dir / "apktool-session"), "--destination", str(analysis_dir / "android" / "apktool")],
                "artifacts": ["android/apktool"],
                "dependency": "apktool",
            },
        ]
    if suffix == ".ipa":
        return [{
            "capability": "ios-static-analysis",
            "provider": "ToolExecutor:ios_analyze",
            "command": [*base, "ios", "analyze", str(source), "--out", str(analysis_dir)],
            "artifacts": ["ios/analysis.json", "semantic-ir.json"],
        }]
    return []


def _file_sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _artifact_evidence(root: Path, relative_path: str) -> dict[str, Any]:
    artifact = root / Path(relative_path)
    if artifact.is_symlink():
        raise ValueError(f"artifact symbolic link is not allowed: {relative_path}")
    if artifact.is_file():
        digest, size = _file_sha256(artifact)
        return {"path": relative_path, "type": "file", "size": size, "sha256": digest}
    if not artifact.is_dir():
        raise ValueError(f"artifact does not exist: {relative_path}")

    entries: list[dict[str, Any]] = []
    total_size = 0
    tree_digest = hashlib.sha256()
    for path in sorted((value for value in artifact.rglob("*") if value.is_file()), key=lambda value: value.relative_to(artifact).as_posix()):
        if path.is_symlink():
            raise ValueError(f"artifact symbolic link is not allowed: {path.relative_to(root).as_posix()}")
        digest, size = _file_sha256(path)
        relative = path.relative_to(artifact).as_posix()
        entry = {"path": relative, "size": size, "sha256": digest}
        entries.append(entry)
        total_size += size
        tree_digest.update(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        tree_digest.update(b"\n")
    return {
        "path": relative_path,
        "type": "directory",
        "size": total_size,
        "file_count": len(entries),
        "sha256": tree_digest.hexdigest(),
        "entries": entries,
    }


def _run_capability_plan(source: Path, analysis_dir: Path, runner: Callable[[Sequence[str]], int]) -> list[dict[str, Any]]:
    stages: list[dict[str, Any]] = []
    for definition in _capability_commands(source, analysis_dir):
        return_code = runner(definition["command"])
        found = [path for path in definition["artifacts"] if (analysis_dir / path).exists()]
        stage = {key: value for key, value in definition.items() if key != "command"}
        stage["command"] = list(definition["command"])
        stage["return_code"] = return_code
        stage["status"] = "completed" if return_code == 0 else "dependency-gated" if definition.get("dependency") else "failed"
        stage["produced_artifacts"] = found
        stage["artifact_evidence"] = [_artifact_evidence(analysis_dir, path) for path in found]
        missing = [path for path in definition["artifacts"] if path not in found]
        stage["artifact_verification"] = {
            "status": "verified" if found else "missing",
            "expected": list(definition["artifacts"]),
            "found": found,
            "missing": missing,
        }
        if stage["status"] == "dependency-gated":
            stage["fallback_reason"] = f"optional dependency or toolchain stage {definition['dependency']} did not complete; see provider audit artifacts"
        stages.append(stage)
    return stages


def _slug(value: str, max_length: int = 32) -> str:
    cleaned = "".join(char.lower() if char.isascii() and char.isalnum() else "_" for char in value).strip("_")
    if not cleaned:
        return f"target_{hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()[:8]}"
    if len(cleaned) <= max_length:
        return cleaned
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"{cleaned[: max_length - 9]}_{digest}"


def _member_path(name: str) -> Path:
    normalized = name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or ".." in pure.parts or any(part.endswith(":") for part in pure.parts):
        raise ValueError(f"unsafe archive member: {name}")
    return Path(*[part for part in pure.parts if part not in {"", "."}])


def _member_name(info: zipfile.ZipInfo) -> str:
    """Recover legacy Chinese ZIP names decoded as CP437 by zipfile."""

    name = info.filename
    if info.flag_bits & 0x800:
        return name
    try:
        candidate = name.encode("cp437").decode("gb18030")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return name
    cjk = sum("\u3400" <= char <= "\u9fff" for char in candidate)
    mojibake = sum("\u2500" <= char <= "\u259f" for char in name)
    return candidate if cjk > 0 and mojibake > 0 else name


def extract_archive(archive_path: Path, destination: Path) -> list[dict[str, Any]]:
    """Extract a ZIP with traversal, link, count and expansion limits."""

    inventory: list[dict[str, Any]] = []
    total = 0
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError(f"archive contains more than {MAX_FILES} entries")
        for info in infos:
            member_name = _member_name(info)
            relative = _member_path(member_name)
            if not relative.parts:
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError(f"archive symbolic link is not allowed: {info.filename}")
            if info.file_size > MAX_FILE_SIZE:
                raise ValueError(f"archive member exceeds size limit: {info.filename}")
            total += info.file_size
            if total > MAX_TOTAL_SIZE:
                raise ValueError("archive expanded size exceeds limit")
            output = destination / relative
            if info.is_dir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            written = 0
            with archive.open(info) as source, output.open("wb") as target:
                while chunk := source.read(1024 * 1024):
                    written += len(chunk)
                    if written > info.file_size or written > MAX_FILE_SIZE:
                        raise ValueError(f"archive member expanded beyond declared size: {info.filename}")
                    digest.update(chunk)
                    target.write(chunk)
            kind, analysis_target, detection = _target_kind(output)
            if kind == "linux-native-executable":
                output.chmod(output.stat().st_mode | stat.S_IXUSR)
            inventory.append({
                "path": relative.as_posix(),
                "size": written,
                "sha256": digest.hexdigest(),
                "kind": kind,
                "analysis_target": analysis_target,
                "detection": detection,
            })
    return inventory


def _find_project(root: Path) -> Path | None:
    candidates = sorted({path.parent for path in root.rglob("project.json") if (path.parent / "CMakeLists.txt").is_file()})
    if not candidates:
        candidates = sorted({path.parent for path in root.rglob("CMakeLists.txt")})
    return candidates[0] if candidates else None


def _default_runner(command: Sequence[str]) -> int:
    return subprocess.run(command, check=False).returncode


def reconstruct_archive(
    archive_path: Path,
    out_dir: Path,
    *,
    runner: Callable[[Sequence[str]], int] = _default_runner,
    model_analyzer: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    build_runner: Callable[..., Any] | None = None,
    behavior_spec: Mapping[str, Any] | str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    archive_path = archive_path.resolve()
    out_dir = out_dir.resolve()
    if not archive_path.is_file() or not zipfile.is_zipfile(archive_path):
        raise ValueError("input is not a readable ZIP archive")
    out_dir.mkdir(parents=True, exist_ok=True)
    network_evidence = _worker_network_evidence()
    workspace = out_dir / "archive-workspace-v3"
    if workspace.exists():
        if workspace.is_symlink() or not workspace.is_dir():
            raise ValueError("managed archive workspace is not a regular directory")
        shutil.rmtree(workspace)
    package_dir = workspace / "package"
    targets_dir = workspace / "target-analysis"
    package_dir.mkdir(parents=True, exist_ok=True)
    targets_dir.mkdir(parents=True, exist_ok=True)
    inventory = extract_archive(archive_path, package_dir)
    candidates = [item for item in inventory if item["analysis_target"]]
    results: list[dict[str, Any]] = []
    used_names: set[str] = set()
    for index, item in enumerate(candidates):
        source = package_dir / Path(item["path"])
        base_name = _slug(Path(item["path"]).stem)
        name = base_name
        while name in used_names:
            name = f"{base_name}_{index + 1}"
        used_names.add(name)
        analysis_dir = targets_dir / name
        stages = _run_capability_plan(source, analysis_dir, runner)
        return_code = next((stage["return_code"] for stage in stages if stage["return_code"] not in {0, 3}), 0)
        project = _find_project(analysis_dir)
        (analysis_dir / "capability-plan.json").parent.mkdir(parents=True, exist_ok=True)
        (analysis_dir / "capability-plan.json").write_text(
            json.dumps(
                {
                    "target": item["path"],
                    "target_evidence": {"size": item["size"], "sha256": item["sha256"]},
                    "stages": stages,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        results.append({
            "id": name,
            "source": item["path"],
            "kind": item["kind"],
            "status": "reconstructed" if project else "analysis-only" if return_code == 0 else "failed",
            "return_code": return_code,
            "analysis_dir": analysis_dir.relative_to(out_dir).as_posix(),
            "project_dir": project.relative_to(out_dir).as_posix() if project else None,
            "capability_plan": (analysis_dir / "capability-plan.json").relative_to(out_dir).as_posix(),
            "capabilities": stages,
        })
    project_dir = compose_project(archive_path, out_dir, workspace, inventory, results)
    (project_dir / "docs" / "worker-network.json").write_text(
        json.dumps(network_evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    from .knowledge.reconstruction_graph import build_reconstruction_graph

    reconstruction_graph = build_reconstruction_graph(project_dir)
    graph_artifact = reconstruction_graph.write_artifact(project_dir / "docs" / "reconstruction-graph.json")
    model_reconstruction = run_model_reconstruction(
        project_dir,
        results,
        model_analyzer=model_analyzer,
        reconstruction_graph=reconstruction_graph,
    )
    graph_artifact = reconstruction_graph.write_artifact(project_dir / "docs" / "reconstruction-graph.json")
    from .source.project_manifest import build_project_manifests

    project_manifests = build_project_manifests(project_dir, results)
    readiness = project_manifests["build_readiness"]
    from .source.project_builder import build_project

    build_result = build_project(project_dir, readiness, model_reconstruction, runner=build_runner)
    from .source.build_repair import run_build_repair_loop

    repair_calls: list[dict[str, Any]] = []
    repair_loop: dict[str, Any] | None = None
    if build_result["status"] in {"failed", "timed_out", "error"} and model_reconstruction["status"] == "executed" and readiness["build_ready"]:
        analyzer = model_analyzer or _default_model_analyzer

        def repair_callback(**repair_context: Any) -> Mapping[str, Any]:
            response = _repair_build_with_model(
                project_dir,
                results,
                reconstruction_graph,
                analyzer,
                str(repair_context["diagnostics"]),
                int(repair_context["iteration"]),
            )
            repair_calls.extend(response["calls"])
            return response

        def rebuild_callback(_root: Path) -> Mapping[str, Any]:
            refreshed = build_project_manifests(project_dir, results)
            return build_project(project_dir, refreshed["build_readiness"], model_reconstruction, runner=build_runner)

        repair_loop = run_build_repair_loop(
            project_dir,
            build_result,
            rebuild_callback,
            repair_callback,
            max_iterations=max(0, int(os.getenv("REVERSE_ANALYZER_BUILD_REPAIR_ITERATIONS", "3"))),
        )
        build_result = dict(repair_loop["final_build_result"])
        _append_build_repairs_to_model_artifact(project_dir, repair_calls, repair_loop)
        model_payload = json.loads((project_dir / "docs" / "model-reconstruction.json").read_text(encoding="utf-8"))
        model_reconstruction["usage"] = dict(model_payload.get("usage") or {})
        model_reconstruction["call_count"] = len(model_payload.get("calls") or [])
        model_reconstruction["applied_change_count"] = int(model_payload.get("applied_change_count") or 0)
    project_manifests = build_project_manifests(project_dir, results)
    readiness = project_manifests["build_readiness"]
    reconstruction_graph.build()
    graph_artifact = reconstruction_graph.write_artifact(project_dir / "docs" / "reconstruction-graph.json")
    graph_payload = reconstruction_graph.to_dict()
    from .source.archive_behavior import DEFAULT_ARCHIVE_BEHAVIOR_PATH, validate_archive_behavior

    selected_behavior_spec = behavior_spec
    current_inventory_paths = {str(item.get("path") or "") for item in inventory}
    if (
        selected_behavior_spec is None
        and "behavior-validation.json" in current_inventory_paths
        and (package_dir / "behavior-validation.json").is_file()
    ):
        selected_behavior_spec = "behavior-validation.json"
    behavior_result = validate_archive_behavior(
        package_dir,
        project_dir,
        selected_behavior_spec,
    )
    behavior_repair_calls: list[dict[str, Any]] = []
    behavior_repair_loop: dict[str, Any] | None = None
    from .source.behavior_repair import is_strict_real_behavior_mismatch

    has_behavior_mismatch = is_strict_real_behavior_mismatch(behavior_result)
    if (
        build_result.get("status") == "passed"
        and build_result.get("build_passed") is True
        and build_result.get("isolated") is True
        and has_behavior_mismatch
        and model_reconstruction.get("status") == "executed"
        and selected_behavior_spec is not None
    ):
        from .source.behavior_repair import run_behavior_repair_loop

        behavior_analyzer = model_analyzer or _default_model_analyzer

        def behavior_repair_callback(**repair_context: Any) -> Mapping[str, Any]:
            response = _repair_behavior_with_model(
                project_dir,
                results,
                reconstruction_graph,
                behavior_analyzer,
                repair_context["behavior_diff"],
                str(repair_context["diagnostics"]),
                int(repair_context["iteration"]),
                remaining_token_budget=int(repair_context["remaining_token_budget"]),
                diagnostic_context_bytes=int(repair_context["diagnostic_context_bytes"]),
            )
            behavior_repair_calls.extend(response["calls"])
            return response

        def behavior_rebuild_callback(_root: Path) -> Mapping[str, Any]:
            refreshed = build_project_manifests(project_dir, results)
            return build_project(
                project_dir,
                refreshed["build_readiness"],
                model_reconstruction,
                runner=build_runner,
            )

        def behavior_revalidate_callback(_root: Path) -> Mapping[str, Any]:
            return validate_archive_behavior(
                package_dir,
                project_dir,
                selected_behavior_spec,
            )

        behavior_repair_loop = run_behavior_repair_loop(
            project_dir,
            behavior_result,
            selected_behavior_spec,
            behavior_repair_callback,
            behavior_rebuild_callback,
            behavior_revalidate_callback,
            max_iterations=max(0, int(os.getenv("REVERSE_ANALYZER_BEHAVIOR_REPAIR_ITERATIONS", "3"))),
            max_token_budget=max(0, int(os.getenv("REVERSE_ANALYZER_BEHAVIOR_REPAIR_TOKEN_BUDGET", "128000"))),
        )
        behavior_result = dict(behavior_repair_loop["final_behavior_result"])
        if isinstance(behavior_repair_loop.get("final_build_result"), Mapping):
            build_result = dict(behavior_repair_loop["final_build_result"])
        _append_behavior_repairs_to_model_artifact(
            project_dir,
            behavior_repair_calls,
            behavior_repair_loop,
        )
        model_payload = json.loads((project_dir / "docs" / "model-reconstruction.json").read_text(encoding="utf-8"))
        model_reconstruction["usage"] = dict(model_payload.get("usage") or {})
        model_reconstruction["call_count"] = len(model_payload.get("calls") or [])
        model_reconstruction["applied_change_count"] = int(model_payload.get("applied_change_count") or 0)
    project_manifests = build_project_manifests(project_dir, results)
    readiness = project_manifests["build_readiness"]
    reconstruction_graph.build()
    graph_artifact = reconstruction_graph.write_artifact(project_dir / "docs" / "reconstruction-graph.json")
    graph_payload = reconstruction_graph.to_dict()
    behavior_summary = behavior_result.get("summary") if isinstance(behavior_result.get("summary"), Mapping) else {}
    manifest = {
        "schema_version": 1,
        "archive": str(archive_path),
        "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        "inventory_count": len(inventory),
        "target_count": len(candidates),
        "inventory": inventory,
        "targets": results,
        "project_dir": str(project_dir),
        "model_reconstruction": model_reconstruction,
        "knowledge_graph": {
            "schema_version": graph_payload["schema_version"],
            "artifact": graph_artifact.relative_to(project_dir).as_posix(),
            "node_count": graph_payload["node_count"],
            "edge_count": graph_payload["edge_count"],
            "fingerprint": graph_payload["fingerprint"],
        },
        "worker_network": {**network_evidence, "artifact": "docs/worker-network.json"},
        "project_readiness": {
            "structure_complete": readiness["structure_complete"],
            "dependencies_locked": readiness["dependencies_locked"],
            "build_ready": readiness["build_ready"],
            "blocking_reasons": readiness["blocking_reasons"],
            "artifacts": project_manifests["artifacts"],
        },
        "automated_build": {
            "status": build_result["status"],
            "build_passed": build_result["build_passed"],
            "isolated": build_result["isolated"],
            "isolation": build_result["isolation"],
            "artifact_count": build_result["artifact_count"],
            "artifact": "docs/build-result.json",
            "blocking_reasons": build_result["blocking_reasons"],
            "repair_status": repair_loop["status"] if repair_loop else "not-required",
            "repair_iterations": repair_loop["iterations_completed"] if repair_loop else 0,
        },
        "behavior_validation": {
            "status": str(behavior_result.get("status") or "failed"),
            "behavior_equivalent": behavior_result.get("behavior_equivalent") is True,
            "blocking_reasons": [str(item) for item in behavior_result.get("blocking_reasons") or []],
            "artifact": DEFAULT_ARCHIVE_BEHAVIOR_PATH.as_posix(),
            "comparison_count": int(behavior_summary.get("comparison_count") or 0),
            "mismatch_count": int(behavior_summary.get("mismatched_comparison_count") or 0),
        },
        "behavior_repair": {
            "status": behavior_repair_loop["status"] if behavior_repair_loop else "not-required",
            "iterations_completed": behavior_repair_loop["iterations_completed"] if behavior_repair_loop else 0,
            "call_count": behavior_repair_loop["call_count"] if behavior_repair_loop else 0,
            "usage": dict(behavior_repair_loop["usage"]) if behavior_repair_loop else {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            "attempted_applied_change_count": behavior_repair_loop["attempted_applied_change_count"] if behavior_repair_loop else 0,
            "applied_change_count": behavior_repair_loop["applied_change_count"] if behavior_repair_loop else 0,
            "blocking_reasons": list(behavior_repair_loop["blocking_reasons"]) if behavior_repair_loop else [],
            "artifact": "docs/behavior-repair-loop.json" if behavior_repair_loop else None,
        },
        "complete_original_source": False,
        "truthfulness": "extracted package files are exact; reconstructed source remains evidence-derived",
    }
    (workspace / "archive-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ok", "project_dir": str(project_dir), "target_count": len(candidates), "inventory_count": len(inventory)}, ensure_ascii=False))
    return manifest


def _worker_network_evidence() -> dict[str, Any]:
    declared = os.getenv("REVERSE_ANALYZER_WORKER_NETWORK", "unknown")
    if declared != "none":
        return {"schema_version": 1, "declared": declared, "probe": {"kind": "not_attempted", "reason": "worker_network_none_not_declared"}, "egress_blocked": False}
    started = time.monotonic()
    code: int | None = None
    error_type: str | None = None
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(1.0)
    try:
        code = probe.connect_ex(("1.1.1.1", 53))
    except OSError as error:
        error_type = type(error).__name__
    finally:
        probe.close()
    blocked = code not in {0, None} or error_type is not None
    return {
        "schema_version": 1,
        "declared": declared,
        "probe": {"kind": "tcp_connect_ex", "destination": "1.1.1.1:53", "return_code": code, "error_type": error_type, "duration_ms": round((time.monotonic() - started) * 1000, 3)},
        "egress_blocked": declared == "none" and blocked,
    }


def run_model_reconstruction(
    project_dir: Path,
    results: list[dict[str, Any]],
    *,
    model_analyzer: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    reconstruction_graph: Any | None = None,
) -> dict[str, Any]:
    context = _model_context(project_dir, results, reconstruction_graph=reconstruction_graph)
    analyzer = model_analyzer or _default_model_analyzer
    artifact_path = project_dir / "docs" / "model-reconstruction.json"
    calls: list[dict[str, Any]] = []
    modules: list[dict[str, Any]] = []
    dependency_edges: list[dict[str, Any]] = []
    usage: dict[str, int] = {}
    token_budget = max(0, int(os.getenv("REVERSE_ANALYZER_MODEL_TOKEN_BUDGET", "0")))
    for target in context["targets"]:
        target_snapshot = dict(target)
        if reconstruction_graph is not None:
            target_snapshot["knowledge_graph"] = reconstruction_graph.module_context(str(target["id"]))
        module_context = {"project": context["project"], "targets": [target_snapshot]}
        call: dict[str, Any] = {"module_id": target["id"], "context": module_context}
        content = ""
        response: dict[str, Any] = {}
        response_usage: dict[str, Any] = {}
        parsed: Mapping[str, Any] | None = None
        if token_budget and usage.get("total_tokens", 0) >= token_budget:
            calls.append({**call, "status": "failed", "provider": os.getenv("REVERSE_ANALYZER_PROVIDER", "rule_based"), "model": os.getenv("OPENAI_MODEL", ""), "result": {}, "raw_response": "", "usage": {}, "error": f"model token budget exhausted ({token_budget})"})
            continue
        try:
            response = dict(analyzer(module_context))
            response_usage = dict(response.get("usage") or {})
            _merge_model_usage(usage, response_usage)
            content = str(response.get("content") or "")
            parsed = response.get("result") if isinstance(response.get("result"), Mapping) else _parse_model_json(content)
            if not isinstance(parsed, Mapping):
                raise ValueError("model response did not contain a structured JSON object")
            call_status = str(response.get("status") or "executed")
            normalized = dict(parsed)
            applied_changes: list[dict[str, Any]] = []
            if call_status == "executed":
                normalized = _validate_model_result(project_dir, target_snapshot, parsed)
                applied_changes = _apply_model_source_changes(project_dir, target, normalized["source_changes"])
                if applied_changes and reconstruction_graph is not None:
                    reconstruction_graph.build()
                    reconstruction_graph.write_artifact(project_dir / "docs" / "reconstruction-graph.json")
            call.update({
                "status": call_status,
                "provider": str(response.get("provider") or "unknown"),
                "model": str(response.get("model") or "unknown"),
                "result": normalized,
                "applied_changes": applied_changes,
                "raw_response": content,
                "usage": dict(response.get("usage") or {}),
            })
            modules.extend(normalized.get("modules", []))
            dependency_edges.extend(normalized.get("dependency_edges", []))
        except Exception as exc:
            parsed_keys = sorted(str(key) for key in parsed) if isinstance(parsed, Mapping) else []
            call.update({
                "status": "failed",
                "provider": str(response.get("provider") or os.getenv("REVERSE_ANALYZER_PROVIDER", "rule_based")),
                "model": str(response.get("model") or os.getenv("OPENAI_MODEL", "")),
                "result": {},
                "raw_response": content,
                "usage": response_usage,
                "error": str(exc),
                "validation": {
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                    "parsed_keys": parsed_keys,
                    "field_types": {str(key): type(value).__name__ for key, value in parsed.items()} if isinstance(parsed, Mapping) else {},
                    "raw_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    "raw_bytes": len(content.encode("utf-8")),
                },
            })
        calls.append(call)

    statuses = [str(call["status"]) for call in calls]
    if "failed" in statuses:
        status = "failed"
    elif statuses and all(value == "executed" for value in statuses):
        status = "executed"
    elif statuses and all(value == "dependency-gated" for value in statuses):
        status = "dependency-gated"
    elif statuses:
        status = "partial"
    else:
        status = "dependency-gated"
    first_call = calls[0] if calls else {}
    payload = {
        "schema_version": 2,
        "status": status,
        "provider": str(first_call.get("provider") or os.getenv("REVERSE_ANALYZER_PROVIDER", "rule_based")),
        "model": str(first_call.get("model") or os.getenv("OPENAI_MODEL", "")),
        "context": context,
        "result": {"modules": modules, "dependency_edges": dependency_edges},
        "calls": calls,
        "applied_change_count": sum(len(call.get("applied_changes") or []) for call in calls),
        "usage": usage,
        "error": "; ".join(f'{call["module_id"]}: {call["error"]}' for call in calls if call.get("error")),
    }
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "status": payload["status"],
        "provider": payload["provider"],
        "model": payload["model"],
        "artifact": artifact_path.relative_to(project_dir).as_posix(),
        "usage": payload["usage"],
        **({"error": payload["error"]} if payload.get("error") else {}),
    }


def _merge_model_usage(total: dict[str, int], current: Mapping[str, Any]) -> None:
    aliases = {
        "prompt_tokens": "input_tokens",
        "completion_tokens": "output_tokens",
    }
    additions: dict[str, int] = {}
    for raw_key, raw_value in current.items():
        key = aliases.get(str(raw_key), str(raw_key))
        if key not in {"input_tokens", "output_tokens", "total_tokens"}:
            continue
        try:
            additions[key] = additions.get(key, 0) + max(0, int(raw_value))
        except (TypeError, ValueError):
            continue
    for key in ("input_tokens", "output_tokens"):
        total[key] = total.get(key, 0) + additions.get(key, 0)
    total["total_tokens"] = total.get("total_tokens", 0) + max(
        additions.get("total_tokens", 0),
        additions.get("input_tokens", 0) + additions.get("output_tokens", 0),
    )


def _default_model_analyzer(context: Mapping[str, Any]) -> Mapping[str, Any]:
    requested = os.getenv("REVERSE_ANALYZER_PROVIDER", "rule_based")
    if requested != "openai_compatible":
        return {
            "status": "dependency-gated",
            "provider": requested,
            "model": "",
            "result": {"modules": [], "dependency_edges": [], "source_changes": [], "blocking_reason": "model_provider_not_selected"},
            "content": "",
            "usage": {},
        }
    from .provider_runtime import ProviderRuntime

    provider = ProviderRuntime().create(requested)
    targets = context.get("targets")
    target = targets[0] if isinstance(targets, list) and len(targets) == 1 and isinstance(targets[0], Mapping) else {}
    module_id = str(target.get("id") or "")
    source_paths = [
        str(item["path"])
        for item in target.get("source_files", [])
        if (
            isinstance(item, Mapping)
            and item.get("path")
            and PurePosixPath(str(item["path"])).suffix.casefold() in {".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".kt", ".py", ".js", ".ts"}
        )
    ]
    graph = target.get("knowledge_graph") if isinstance(target.get("knowledge_graph"), Mapping) else {}
    graph_evidence = [
        str(item["id"])
        for field in ("nodes", "edges")
        for item in graph.get(field, [])
        if isinstance(item, Mapping) and item.get("id")
    ]
    behavior_repair = context.get("behavior_repair") if isinstance(context.get("behavior_repair"), Mapping) else None
    if behavior_repair is not None:
        diagnostic = behavior_repair.get("diagnostic_context") if isinstance(behavior_repair.get("diagnostic_context"), Mapping) else {}
        observations = [
            {
                "name": item.get("name"),
                "kind": item.get("kind"),
                "matched": item.get("matched"),
                "original_observation": item.get("original_observation"),
                "reconstructed_observation": item.get("reconstructed_observation"),
            }
            for item in diagnostic.get("comparisons", [])
            if isinstance(item, Mapping)
        ]
        repair_recipe: dict[str, Any] = {"outputs": [], "implementation_rules": [
            "Use the target language standard I/O APIs to emit the exact observed streams.",
            "Create each observed output path before returning.",
            "For a hash-only output, inspect recovered string literals and choose content whose encoded size matches the observed size; include the observed line ending.",
            "Return the exact observed process exit code after all writes succeed.",
        ]}
        candidates: list[dict[str, Any]] = []
        for source_file in target.get("source_files", []):
            if not isinstance(source_file, Mapping) or not isinstance(source_file.get("preview"), str):
                continue
            for encoded in re.findall(r'"((?:\\.|[^"\\])*)"', source_file["preview"]):
                try:
                    value = json.loads(f'"{encoded}"')
                except json.JSONDecodeError:
                    continue
                if value and value not in {item["value"] for item in candidates}:
                    candidates.append({
                        "value": value,
                        "utf8_bytes": len(value.encode("utf-8")),
                        "utf8_bytes_with_newline": len((value + "\n").encode("utf-8")),
                    })
                if len(candidates) >= 80:
                    break
        repair_recipe["recovered_string_candidates"] = candidates
        for observation in observations:
            original = observation.get("original_observation")
            if not isinstance(original, Mapping):
                continue
            name = str(observation.get("name") or "")
            if name == "exit_code" and isinstance(original.get("exit_code"), int):
                repair_recipe["exit_code"] = original["exit_code"]
            elif name in {"stdout", "stderr"} and isinstance(original.get("text"), str):
                repair_recipe[f"{name}_text"] = original["text"]
            elif original.get("path"):
                repair_recipe["outputs"].append({
                    key: original.get(key) for key in ("path", "kind", "sha256", "size_bytes") if original.get(key) is not None
                })
        task = (
            "Repair the existing module source so reconstructed behavior exactly matches the original observations. "
            "Use the original exit code and plaintext stdout/stderr observations literally, create every required "
            "output file using recovered string evidence, and preserve buildability. Implement every field in the "
            "repair_recipe using standard I/O; do not merely edit comments or retain the old main body. You MUST return "
            "changed complete source content; returning the current source unchanged is invalid. Repair recipe: "
            + json.dumps(repair_recipe, ensure_ascii=False, separators=(",", ":"))
        )
    else:
        task = (
            "Recover exactly the requested module and return only one JSON object matching output_schema. "
            "Copy required field names exactly. The single module object must contain id, responsibility, "
            "interfaces, missing_implementations, and evidence. Every source_changes path must be copied "
            "verbatim from allowed_source_paths; never emit an absolute path. Every source change must be a "
            "complete file implementation and cite at least one allowed_source_path in evidence."
        )
    reconstruction_payload: Mapping[str, Any] = dict(context)
    if behavior_repair is not None:
        code_files = [item for item in target.get("source_files", []) if isinstance(item, Mapping) and str(item.get("path") or "") in source_paths]
        reconstruction_payload = {
            "project": context.get("project"),
            "target": {"id": module_id, "source_files": code_files},
            "behavior_repair": dict(behavior_repair),
            "repair_recipe": repair_recipe,
        }
    message = provider.analyze({
        "task": task,
        "phase": "behavior_repair" if behavior_repair is not None else "module_reconstruction",
        "strict_output_contract": {
            "module_id": module_id,
            "module_count": 1,
            "required_module_fields": ["id", "responsibility", "interfaces", "missing_implementations", "evidence"],
            "allowed_source_paths": source_paths,
            "allowed_graph_evidence": graph_evidence,
            "source_change_count_minimum": 1,
            "absolute_paths_forbidden": True,
        },
        "reconstruction": reconstruction_payload,
        "max_output_tokens": (
            context.get("behavior_repair", {}).get("max_output_tokens")
            if isinstance(context.get("behavior_repair"), Mapping)
            else None
        ),
        "output_schema": {
            "modules": [{"id": "string", "responsibility": "string", "interfaces": [], "missing_implementations": [], "evidence": []}],
            "dependency_edges": [{"source": "string", "target": "string", "reason": "string"}],
            "source_changes": [{
                "path": source_paths[0] if source_paths else "no-source-path-available",
                "content": "complete file content",
                "reason": "string",
                "evidence": [source_paths[0] if source_paths else "no-source-path-available"],
            }],
        },
    })
    if message.barrier:
        raise RuntimeError(message.final_answer or message.content or "model provider is unavailable")
    metadata = dict(message.metadata)
    return {
        "status": "executed",
        "provider": requested,
        "model": str(metadata.get("model") or os.getenv("OPENAI_MODEL", "")),
        "content": message.final_answer or message.content,
        "usage": dict(metadata.get("usage") or {}),
    }


def _validate_model_result(project_dir: Path, target: Mapping[str, Any], value: Mapping[str, Any]) -> dict[str, Any]:
    module_id = str(target["id"])
    modules = value.get("modules")
    edges = value.get("dependency_edges")
    changes = value.get("source_changes")
    if not isinstance(modules, list) or len(modules) != 1 or not isinstance(modules[0], Mapping):
        raise ValueError("model result must contain exactly one module object")
    module = dict(modules[0])
    if str(module.get("id") or "") != module_id:
        raise ValueError(f"model module id must match {module_id}")
    if not isinstance(module.get("responsibility"), str) or not str(module["responsibility"]).strip():
        raise ValueError("model module responsibility must be a non-empty string")
    for field in ("interfaces", "missing_implementations", "evidence"):
        if not isinstance(module.get(field), list):
            raise ValueError(f"model module {field} must be an array")
    if not isinstance(edges, list) or any(not isinstance(item, Mapping) for item in edges):
        raise ValueError("dependency_edges must be an array of objects")
    if not isinstance(changes, list) or not changes:
        raise ValueError("source_changes must contain at least one completed source file")
    source_evidence = {str(item["path"]) for item in target.get("source_files", []) if isinstance(item, Mapping) and item.get("path")}
    graph_context = target.get("knowledge_graph") if isinstance(target.get("knowledge_graph"), Mapping) else {}
    graph_evidence = {
        str(item["id"])
        for field in ("nodes", "edges")
        for item in graph_context.get(field, [])
        if isinstance(item, Mapping) and item.get("id")
    }
    allowed_evidence = source_evidence | graph_evidence
    normalized_changes: list[dict[str, Any]] = []
    prefix = f"targets/{module_id}/"
    for raw_change in changes:
        if not isinstance(raw_change, Mapping):
            raise ValueError("each source change must be an object")
        change = dict(raw_change)
        relative = str(change.get("path") or "").replace("\\", "/")
        content = change.get("content")
        evidence = change.get("evidence")
        if not relative.startswith(prefix) or ".." in PurePosixPath(relative).parts:
            raise ValueError(f"source change path escapes module {module_id}: {relative}")
        destination = project_dir / Path(relative)
        if not destination.is_file() or destination.suffix.casefold() not in {".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".kt", ".py", ".js", ".ts"}:
            raise ValueError(f"source change must target an existing source file: {relative}")
        if not isinstance(content, str) or not content.strip():
            raise ValueError(f"source change content is empty: {relative}")
        max_source_bytes = max(1, int(os.getenv("REVERSE_ANALYZER_MODEL_MAX_SOURCE_BYTES", str(1 << 20))))
        if len(content.encode("utf-8")) > max_source_bytes:
            raise ValueError(f"source change exceeds {max_source_bytes} bytes: {relative}")
        lowered = content.casefold()
        if any(marker in lowered for marker in ("todo", "notimplemented", "placeholder")):
            raise ValueError(f"source change still contains an incomplete implementation marker: {relative}")
        if (
            not isinstance(evidence, list)
            or not evidence
            or any(str(item) not in allowed_evidence for item in evidence)
            or not any(str(item) in source_evidence for item in evidence)
        ):
            raise ValueError(f"source change evidence must reference context files: {relative}")
        change.update({"path": relative, "content": content, "evidence": [str(item) for item in evidence]})
        normalized_changes.append(change)
    return {"modules": [module], "dependency_edges": [dict(item) for item in edges], "source_changes": normalized_changes}


def _apply_model_source_changes(project_dir: Path, target: Mapping[str, Any], changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for change in changes:
        destination = project_dir / Path(change["path"])
        before = destination.read_text(encoding="utf-8", errors="replace")
        after = str(change["content"])
        records.append({
            "module_id": str(target["id"]),
            "path": str(change["path"]),
            "reason": str(change.get("reason") or "model source completion"),
            "evidence": list(change["evidence"]),
            "before_sha256": hashlib.sha256(before.encode("utf-8")).hexdigest(),
            "after_sha256": hashlib.sha256(after.encode("utf-8")).hexdigest(),
            "diff": "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=str(change["path"]), tofile=str(change["path"]))),
        })
        destination.write_text(after, encoding="utf-8")
    audit = project_dir / "docs" / "model-source-changes" / f'{target["id"]}.json'
    audit.parent.mkdir(parents=True, exist_ok=True)
    audit.write_text(json.dumps({"schema_version": 1, "module_id": target["id"], "changes": records}, ensure_ascii=False, indent=2), encoding="utf-8")
    return records


def _repair_build_with_model(
    project_dir: Path,
    results: list[dict[str, Any]],
    reconstruction_graph: Any,
    analyzer: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    diagnostics: str,
    iteration: int,
) -> dict[str, Any]:
    context = _model_context(project_dir, results, reconstruction_graph=reconstruction_graph)
    selected_ids = {
        str(result["id"])
        for result in results
        if f'targets/{result["id"]}/' in diagnostics.replace("\\", "/")
    }
    selected = [target for target in context["targets"] if not selected_ids or str(target["id"]) in selected_ids]
    calls: list[dict[str, Any]] = []
    applied: list[dict[str, Any]] = []
    usage: dict[str, int] = {}
    for target in selected:
        module_context = {
            "project": context["project"],
            "targets": [target],
            "build_repair": {"iteration": iteration, "diagnostics": diagnostics},
        }
        content = ""
        call: dict[str, Any] = {"phase": "build-repair", "iteration": iteration, "module_id": target["id"], "context": module_context}
        try:
            response = dict(analyzer(module_context))
            content = str(response.get("content") or "")
            parsed = response.get("result") if isinstance(response.get("result"), Mapping) else _parse_model_json(content)
            if str(response.get("status") or "executed") != "executed" or not isinstance(parsed, Mapping):
                raise ValueError("build repair model response was not an executed structured result")
            normalized = _validate_model_result(project_dir, target, parsed)
            changes = _apply_model_source_changes(project_dir, target, normalized["source_changes"])
            call.update({
                "status": "executed",
                "provider": str(response.get("provider") or "unknown"),
                "model": str(response.get("model") or "unknown"),
                "result": normalized,
                "applied_changes": changes,
                "raw_response": content,
                "usage": dict(response.get("usage") or {}),
            })
            applied.extend(changes)
            _merge_model_usage(usage, call["usage"])
        except Exception as exc:
            call.update({"status": "failed", "raw_response": content, "usage": {}, "error": str(exc), "applied_changes": []})
        calls.append(call)
    artifact = project_dir / "docs" / "model-build-repairs" / f"iteration-{iteration:02d}.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps({"schema_version": 1, "iteration": iteration, "calls": calls, "usage": usage}, ensure_ascii=False, indent=2), encoding="utf-8")
    if applied:
        reconstruction_graph.build()
        reconstruction_graph.write_artifact(project_dir / "docs" / "reconstruction-graph.json")
    first = calls[0] if calls else {}
    failures = [call for call in calls if call["status"] != "executed"]
    return {
        "applied_changes": [] if failures else applied,
        "provider": first.get("provider"),
        "model": first.get("model"),
        "usage": usage,
        "calls": calls,
        "raw_response_artifact": artifact.relative_to(project_dir).as_posix(),
        **({"error": "; ".join(f'{call["module_id"]}: {call.get("error")}' for call in failures)} if failures else {}),
    }


def _append_build_repairs_to_model_artifact(project_dir: Path, calls: list[dict[str, Any]], repair_loop: Mapping[str, Any]) -> None:
    artifact = project_dir / "docs" / "model-reconstruction.json"
    try:
        payload = json.loads(artifact.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return
    existing_calls = payload.get("calls") if isinstance(payload.get("calls"), list) else []
    existing_calls.extend(calls)
    payload["calls"] = existing_calls
    usage = dict(payload.get("usage") or {})
    _merge_model_usage(usage, repair_loop.get("usage") if isinstance(repair_loop.get("usage"), Mapping) else {})
    payload["usage"] = usage
    payload["applied_change_count"] = int(payload.get("applied_change_count") or 0) + sum(len(call.get("applied_changes") or []) for call in calls)
    payload["build_repair"] = {
        "status": repair_loop.get("status"),
        "iterations_completed": repair_loop.get("iterations_completed"),
        "artifact": "docs/build-repair-loop.json",
    }
    artifact.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _repair_behavior_with_model(
    project_dir: Path,
    results: list[dict[str, Any]],
    reconstruction_graph: Any,
    analyzer: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    behavior_diff: Mapping[str, Any],
    diagnostics: str,
    iteration: int,
    *,
    remaining_token_budget: int = 128_000,
    diagnostic_context_bytes: int | None = None,
) -> dict[str, Any]:
    reconstruction_graph.build()
    reconstruction_graph.write_artifact(project_dir / "docs" / "reconstruction-graph.json")
    context = _model_context(project_dir, results, reconstruction_graph=reconstruction_graph)
    evidence_text = json.dumps(behavior_diff, ensure_ascii=False) + "\n" + diagnostics
    selected_ids = {
        str(result["id"])
        for result in results
        if f'targets/{result["id"]}/' in evidence_text.replace("\\", "/")
    }
    selected = [target for target in context["targets"] if not selected_ids or str(target["id"]) in selected_ids]
    calls: list[dict[str, Any]] = []
    applied: list[dict[str, Any]] = []
    staged: list[tuple[Mapping[str, Any], dict[str, Any], dict[str, Any]]] = []
    usage: dict[str, int] = {}
    budget_unavailable = False
    for target in selected:
        module_token_budget = max(0, remaining_token_budget - int(usage.get("total_tokens", 0)))
        if module_token_budget == 0:
            budget_unavailable = True
            break
        module_context = {
            "project": context["project"],
            "targets": [target],
            "behavior_repair": {
                "iteration": iteration,
                "diagnostic_context": dict(behavior_diff),
                "diagnostic_context_bytes": (
                    diagnostic_context_bytes
                    if diagnostic_context_bytes is not None
                    else len(json.dumps(behavior_diff, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
                ),
                "remaining_token_budget": module_token_budget,
                "max_output_tokens": module_token_budget,
                "requirement": "Make reconstructed behavior match the original while preserving buildability.",
            },
        }
        content = ""
        response_usage: dict[str, Any] = {}
        call: dict[str, Any] = {
            "phase": "behavior-repair",
            "iteration": iteration,
            "module_id": target["id"],
            "context": module_context,
        }
        try:
            raw_response = analyzer(module_context)
        except Exception as exc:
            call.update({
                "status": "failed",
                "error_kind": "provider_unavailable",
                "raw_response": "",
                "usage": {},
                "error": f"{type(exc).__name__}: {exc}",
                "applied_changes": [],
            })
            calls.append(call)
            continue
        try:
            if not isinstance(raw_response, Mapping):
                raise TypeError("behavior repair analyzer must return a mapping")
            response = dict(raw_response)
            content = str(response.get("content") or "")
            response_usage = dict(response.get("usage") or {})
            _merge_model_usage(usage, response_usage)
            parsed = response.get("result") if isinstance(response.get("result"), Mapping) else _parse_model_json(content)
            if str(response.get("status") or "executed") != "executed" or not isinstance(parsed, Mapping):
                raise ValueError("behavior repair model response was not an executed structured result")
            normalized = _validate_model_result(project_dir, target, parsed)
            if all(
                (project_dir / Path(change["path"])).read_text(encoding="utf-8", errors="replace") == str(change["content"])
                for change in normalized["source_changes"]
            ):
                raise ValueError("behavior repair must change at least one source file")
            call.update({
                "status": "executed",
                "provider": str(response.get("provider") or "unknown"),
                "model": str(response.get("model") or "unknown"),
                "result": normalized,
                "applied_changes": [],
                "raw_response": content,
                "usage": response_usage,
            })
            staged.append((target, normalized, call))
        except Exception as exc:
            call.update({
                "status": "failed",
                "error_kind": "invalid_response",
                "raw_response": content,
                "usage": response_usage,
                "error": f"{type(exc).__name__}: {exc}",
                "applied_changes": [],
            })
        calls.append(call)
    budget_exceeded = budget_unavailable or int(usage.get("total_tokens", 0)) > remaining_token_budget
    if budget_exceeded:
        for call in calls:
            call["applied_changes"] = []
    failures = [call for call in calls if call["status"] != "executed"]
    apply_error: str | None = None
    if not budget_exceeded and not failures and len(staged) == len(selected):
        source_snapshot = _snapshot_composite_targets(project_dir)
        try:
            for target, normalized, call in staged:
                changes = _apply_model_source_changes(project_dir, target, normalized["source_changes"])
                call["applied_changes"] = changes
                applied.extend(changes)
        except Exception as exc:
            _restore_composite_targets(project_dir, source_snapshot)
            reconstruction_graph.build()
            reconstruction_graph.write_artifact(project_dir / "docs" / "reconstruction-graph.json")
            applied.clear()
            for call in calls:
                call["applied_changes"] = []
            apply_error = f"{type(exc).__name__}: {exc}"
    artifact = project_dir / "docs" / "model-behavior-repairs" / f"iteration-{iteration:02d}.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(
        json.dumps({"schema_version": 1, "iteration": iteration, "calls": calls, "usage": usage}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    first = calls[0] if calls else {}
    failures = [call for call in calls if call["status"] != "executed"]
    status = "failed" if budget_exceeded or failures or apply_error else "executed"
    error_kind = (
        "token_budget_exceeded"
        if budget_exceeded
        else "apply_failed"
        if apply_error
        else "provider_unavailable"
        if any(call.get("error_kind") == "provider_unavailable" for call in failures)
        else "invalid_response"
        if failures
        else None
    )
    return {
        "status": status,
        "error_kind": error_kind,
        "applied_changes": [] if failures else applied,
        "provider": first.get("provider"),
        "model": first.get("model"),
        "usage": usage,
        "calls": calls,
        "raw_response_artifact": artifact.relative_to(project_dir).as_posix(),
        **(
            {"error": f"behavior repair response usage exceeded remaining token budget ({remaining_token_budget})"}
            if budget_exceeded
            else {"error": apply_error}
            if apply_error
            else {"error": "; ".join(f'{call["module_id"]}: {call.get("error")}' for call in failures)}
            if failures
            else {}
        ),
    }


def _snapshot_composite_targets(project_dir: Path) -> dict[str, bytes]:
    targets = project_dir / "targets"
    if not targets.is_dir():
        return {}
    return {
        path.relative_to(project_dir).as_posix(): path.read_bytes()
        for path in targets.rglob("*")
        if path.is_file()
    }


def _restore_composite_targets(project_dir: Path, snapshot: Mapping[str, bytes]) -> None:
    targets = project_dir / "targets"
    if targets.is_dir():
        for path in targets.rglob("*"):
            if path.is_file() and path.relative_to(project_dir).as_posix() not in snapshot:
                path.unlink()
    for relative, content in snapshot.items():
        path = project_dir / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def _append_behavior_repairs_to_model_artifact(
    project_dir: Path,
    calls: list[dict[str, Any]],
    repair_loop: Mapping[str, Any],
) -> None:
    artifact = project_dir / "docs" / "model-reconstruction.json"
    try:
        payload = json.loads(artifact.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return
    existing_calls = payload.get("calls") if isinstance(payload.get("calls"), list) else []
    existing_calls.extend(calls)
    payload["calls"] = existing_calls
    usage = dict(payload.get("usage") or {})
    repair_usage = repair_loop.get("usage")
    _merge_model_usage(usage, repair_usage if isinstance(repair_usage, Mapping) else {})
    payload["usage"] = usage
    payload["applied_change_count"] = int(payload.get("applied_change_count") or 0) + int(
        repair_loop.get("applied_change_count") or 0
    )
    payload["behavior_repair"] = {
        "status": repair_loop.get("status"),
        "iterations_completed": repair_loop.get("iterations_completed"),
        "call_count": repair_loop.get("call_count"),
        "usage": dict(repair_loop.get("usage") or {}),
        "attempted_applied_change_count": repair_loop.get("attempted_applied_change_count"),
        "applied_change_count": repair_loop.get("applied_change_count"),
        "artifact": "docs/behavior-repair-loop.json",
    }
    artifact.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _model_context(
    project_dir: Path,
    results: list[dict[str, Any]],
    *,
    reconstruction_graph: Any | None = None,
) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    for result in results:
        target_dir = project_dir / "targets" / str(result["id"])
        source_files: list[dict[str, Any]] = []
        if target_dir.is_dir():
            for path in sorted(target_dir.rglob("*")):
                if not path.is_file() or len(source_files) >= MODEL_CONTEXT_FILE_LIMIT:
                    continue
                relative = path.relative_to(project_dir).as_posix()
                suffix = path.suffix.casefold()
                item: dict[str, Any] = {"path": relative, "size": path.stat().st_size}
                if suffix in {".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".kt", ".smali", ".py", ".js", ".ts", ".xml", ".json"}:
                    item["preview"] = path.read_text(encoding="utf-8", errors="replace")[:MODEL_CONTEXT_PREVIEW_LIMIT]
                source_files.append(item)
        target_context = {
            "id": result["id"],
            "source": result["source"],
            "kind": result["kind"],
            "status": result["status"],
            "capabilities": result.get("capabilities") or [],
            "source_files": source_files,
        }
        if reconstruction_graph is not None:
            target_context["knowledge_graph"] = reconstruction_graph.module_context(str(result["id"]))
        targets.append(target_context)
    return {"project": project_dir.name, "targets": targets}


def _parse_model_json(content: str) -> Mapping[str, Any] | None:
    value = content.strip()
    if value.startswith("```"):
        lines = value.splitlines()
        value = "\n".join(lines[1:-1] if len(lines) >= 3 else lines)
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _ensure_native_source_scaffold(destination: Path, module_id: str, kind: str) -> bool:
    """Create a real model-editable build target when decompilation yielded no project."""

    if kind not in {
        "windows-executable",
        "windows-library",
        "linux-native-executable",
        "linux-native-library",
    }:
        return False
    source = destination / "source" / "main.c"
    source.parent.mkdir(parents=True, exist_ok=True)
    if not source.is_file():
        source.write_text(
            "/* Evidence-driven reconstruction entry point; completed by the model stage. */\n"
            "int reconstructed_module(void) { return 0; }\n",
            encoding="utf-8",
        )
    target_name = "module_" + _slug(module_id).replace("-", "_")
    command = "add_library" if kind.endswith("library") else "add_executable"
    kind_arg = " SHARED" if command == "add_library" else ""
    cmake = destination / "CMakeLists.txt"
    if not cmake.is_file():
        cmake.write_text(
            "cmake_minimum_required(VERSION 3.16)\n"
            f"project({target_name} LANGUAGES C)\n"
            f"{command}({target_name}{kind_arg} source/main.c)\n",
            encoding="utf-8",
        )
    return True


def compose_project(archive_path: Path, out_dir: Path, workspace: Path, inventory: list[dict[str, Any]], results: list[dict[str, Any]]) -> Path:
    project = out_dir / f"reconstructed_archive_{_slug(archive_path.stem)}"
    if project.exists():
        shutil.rmtree(project)
    (project / "targets").mkdir(parents=True)
    (project / "docs").mkdir(parents=True)
    (project / "scripts").mkdir(parents=True)
    shutil.copytree(workspace / "package", project / "package")
    cmake_lines = ["cmake_minimum_required(VERSION 3.16)", f"project(reconstructed_archive_{_slug(archive_path.stem)} LANGUAGES C CXX)", ""]
    copied_results: list[dict[str, Any]] = []
    for result in results:
        item = dict(result)
        raw_project = result.get("project_dir")
        raw_analysis = out_dir / str(result["analysis_dir"])
        destination = project / "targets" / str(result["id"])
        if raw_project:
            source = out_dir / str(raw_project)
            shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".build", "CMakeFiles"))
            item["composite_path"] = destination.relative_to(project).as_posix()
            if (destination / "CMakeLists.txt").is_file():
                cmake_lines.append(f'add_subdirectory("targets/{result["id"]}")')
        else:
            destination.mkdir(parents=True, exist_ok=True)
            item["composite_path"] = destination.relative_to(project).as_posix()
            if result.get("kind") == "android-package":
                apk_source = workspace / "package" / Path(str(result["source"]))
                if zipfile.is_zipfile(apk_source):
                    apk_inventory = extract_archive(apk_source, destination / "package")
                    item["exact_package_extraction"] = True
                    item["package_file_count"] = len(apk_inventory)
                    (destination / "package-inventory.json").write_text(
                        json.dumps(apk_inventory, ensure_ascii=False, indent=2), encoding="utf-8"
                    )
            (destination / "README.md").write_text(
                "# Target status\n\n"
                f"Source package: `{result['source']}`\n\n"
                "The package tree is extracted exactly. Source decompilation is dependency-gated and has not been represented as original source.\n",
                encoding="utf-8",
            )
            if _ensure_native_source_scaffold(destination, str(result["id"]), str(result.get("kind") or "")):
                item["model_source_scaffold"] = (destination / "source" / "main.c").relative_to(project).as_posix()
                cmake_lines.append(f'add_subdirectory("targets/{result["id"]}")')
        capability_plan = raw_analysis / "capability-plan.json"
        if capability_plan.is_file():
            shutil.copy2(capability_plan, destination / "capability-plan.json")
        gui_projects = sorted(path for path in raw_analysis.glob("reconstructed_gui*") if path.is_dir())
        if gui_projects:
            shutil.copytree(gui_projects[0], destination / "gui", dirs_exist_ok=True)
            item["gui_project"] = (destination / "gui").relative_to(project).as_posix()
        if result.get("kind") == "android-package":
            source_root = destination / "source"
            jadx_source = raw_analysis / "android" / "source"
            apktool_source = raw_analysis / "android" / "apktool"
            if jadx_source.is_dir():
                shutil.copytree(jadx_source, source_root / "java-kotlin", dirs_exist_ok=True)
                item["java_kotlin_source"] = (source_root / "java-kotlin").relative_to(project).as_posix()
            if apktool_source.is_dir():
                shutil.copytree(apktool_source, source_root / "apktool", dirs_exist_ok=True)
                item["smali_resource_source"] = (source_root / "apktool").relative_to(project).as_posix()
        copied_results.append(item)
    (project / "CMakeLists.txt").write_text("\n".join(cmake_lines) + "\n", encoding="utf-8")
    (project / "scripts" / "build.sh").write_text("#!/bin/sh\nset -eu\ncmake -S . -B .build\ncmake --build .build\n", encoding="utf-8")
    (project / "scripts" / "build.ps1").write_text("$ErrorActionPreference = 'Stop'\ncmake -S . -B .build\ncmake --build .build --config Release\n", encoding="utf-8")
    report = [
        "# Archive reconstruction status",
        "",
        "The package/ tree is an exact extraction of the submitted archive.",
        "The targets/ tree contains evidence-derived reconstructions and is not claimed to be the original source repository.",
        "",
        f"- Extracted files: {len(inventory)}",
        f"- Analysis targets: {len(results)}",
        f"- Reconstructed targets: {sum(1 for item in results if item['status'] == 'reconstructed')}",
    ]
    (project / "README.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    (project / "docs" / "reconstruction-status.json").write_text(json.dumps({"targets": copied_results, "complete_original_source": False}, ensure_ascii=False, indent=2), encoding="utf-8")
    (project / "docs" / "package-inventory.json").write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")
    return project


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Safely reconstruct mixed targets from a ZIP archive")
    parser.add_argument("archive")
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--behavior-spec",
        help="ZIP 包内行为验证 JSON 的相对路径；默认使用根目录 behavior-validation.json",
    )
    args = parser.parse_args(argv)
    try:
        reconstruct_archive(Path(args.archive), Path(args.out), behavior_spec=args.behavior_spec)
        return 0
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
