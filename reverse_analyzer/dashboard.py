"""Offline dashboard generation for reverse-engineering experiment workspaces."""

from __future__ import annotations

from datetime import datetime, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any, Iterable

from .dashboard_platform_core import build_platform_core_view
from .source_reconstruction import summarize_source_reconstruction


def build_dashboard(
    workspace: str | Path,
    *,
    out_dir: str | Path | None = None,
    knowledge_dir: str | Path | None = None,
) -> dict:
    """Build an offline dashboard and return the JSON-compatible dashboard data."""

    root = Path(workspace)
    destination = Path(out_dir) if out_dir is not None else root / "dashboard"
    knowledge_root = (
        Path(knowledge_dir)
        if knowledge_dir is not None
        else root / ".reverse_analyzer" / "knowledge"
    )
    diagnostics: dict[str, Any] = {
        "files_scanned": 0,
        "files_loaded": 0,
        "malformed_json": 0,
        "invalid_records": 0,
        "skipped_files": [],
    }

    experiments = _load_records((root / "experiments",), diagnostics)
    sessions = _load_records(_session_directories(root), diagnostics)
    dynamic_profiles = _load_json(knowledge_root / "dynamic_profiles.json", diagnostics)
    gui_strategies = _load_json(knowledge_root / "gui_strategies.json", diagnostics)
    source_reconstruction = summarize_source_reconstruction(root)
    binary_patches = _load_binary_patches(root, diagnostics)
    evidence_manifests = _load_evidence_manifests(root, diagnostics)
    platform_core_report = _load_platform_core_report(root, diagnostics)

    experiments.sort(key=_record_timestamp, reverse=True)
    sessions.sort(key=_record_timestamp, reverse=True)
    status_counts: dict[str, int] = {}
    for experiment in experiments:
        status = str(experiment.get("status") or "unknown").lower()
        status_counts[status] = status_counts.get(status, 0) + 1

    data = {
        "generated_at": _utc_now(),
        "summary": {
            "experiment_total": len(experiments),
            "status_counts": status_counts,
            "session_total": len(sessions),
            "completed_total": status_counts.get("completed", 0),
        },
        "experiments": experiments[:50],
        "sessions": sessions[:20],
        "recommendations": {
            "dynamic_profile": _recommend_dynamic_profile(dynamic_profiles),
            "gui_strategy": _recommend_gui_strategy(gui_strategies),
        },
        "source_reconstruction": source_reconstruction,
        "binary_patches": binary_patches,
        "evidence_manifests": evidence_manifests,
        "platform_core": build_platform_core_view(platform_core_report),
        "diagnostics": diagnostics,
    }

    destination.mkdir(parents=True, exist_ok=True)
    _write_json(destination / "data.json", data)
    (destination / "index.html").write_text(_html_document(data), encoding="utf-8")
    return data


def serve_dashboard(
    directory: str | Path, *, host: str = "127.0.0.1", port: int = 0
) -> ThreadingHTTPServer:
    """Create a dashboard HTTP server without entering its serving loop."""

    handler = partial(SimpleHTTPRequestHandler, directory=str(Path(directory)))
    return ThreadingHTTPServer((host, port), handler)



def _load_platform_core_report(workspace: Path, diagnostics: dict[str, Any]) -> dict[str, Any]:
    candidates = []
    try:
        candidates = sorted(workspace.rglob("report.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    except OSError:
        candidates = []
    for path in candidates:
        payload = _load_json(path, diagnostics)
        if isinstance(payload, dict) and isinstance(payload.get("platform_core"), dict):
            return payload
    return {"platform_core": {"status": "unavailable"}}

def _session_directories(workspace: Path) -> tuple[Path, ...]:
    """Return top-level and local-runner session directories for a workspace."""

    experiment_root = workspace / "experiments"
    local_session_dirs = (
        tuple(sorted(path for path in experiment_root.glob("*/analysis/sessions") if path.is_dir()))
        if experiment_root.is_dir()
        else ()
    )
    return (workspace / "sessions", *local_session_dirs)


def _load_records(
    directories: Iterable[Path], diagnostics: dict[str, Any]
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    for directory in directories:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            source_path = path.resolve()
            if source_path in seen_paths:
                continue
            seen_paths.add(source_path)
            value = _load_json(path, diagnostics)
            if isinstance(value, dict):
                record = dict(value)
                record.setdefault("source_file", path.name)
                records.append(record)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        record = dict(item)
                        record.setdefault("source_file", path.name)
                        records.append(record)
                    else:
                        diagnostics["invalid_records"] += 1
            elif value is not None:
                diagnostics["invalid_records"] += 1
    return records


def _load_json(path: Path, diagnostics: dict[str, Any]) -> Any:
    if not path.is_file():
        return None
    diagnostics["files_scanned"] += 1
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        diagnostics["malformed_json"] += 1
        diagnostics["skipped_files"].append({"path": str(path), "error": str(error)})
        return None
    diagnostics["files_loaded"] += 1
    return value


def _record_timestamp(record: dict[str, Any]) -> str:
    for key in ("updated_at", "timestamp", "created_at", "started_at"):
        value = record.get(key)
        if value is not None:
            return str(value)
    return ""


def _load_binary_patches(workspace: Path, diagnostics: dict[str, Any]) -> dict[str, Any]:
    """Collect structurally valid, output-associated patch audit manifests.

    Patch commands may write artifacts beside a requested output, so manifests
    are discovered recursively rather than assuming one fixed session layout.
    A file merely named ``patch_manifest.json`` is not sufficient evidence of a
    completed patch: it must match the patch tool's schema and either live in
    the default patch-artifact directory or have a matching rollback plan.
    A patch manifest and its rollback instructions in the same directory describe
    one patch audit item. A rollback result manifest is a separate audit item.
    """

    artifacts: dict[tuple[Path, str], dict[str, Any]] = {}
    try:
        paths = sorted(
            {
                *workspace.rglob("patch_manifest.json"),
                *workspace.rglob("rollback.json"),
                *workspace.rglob("rollback_manifest.json"),
            },
            key=lambda path: str(path),
        )
    except OSError:
        paths = []

    loaded: dict[Path, dict[str, Any]] = {}
    for path in paths:
        value = _load_json(path, diagnostics)
        if not isinstance(value, dict):
            if value is not None:
                diagnostics["invalid_records"] += 1
            continue
        loaded[path] = value

    for path, value in loaded.items():
        # ``rollback.json`` contains restoration instructions for a patch
        # audit, not a separately applied patch result.  It is consulted below
        # only to prove a custom artifact directory belongs to the patch tool.
        if path.name == "rollback.json":
            continue
        audit_type = "rollback" if path.name == "rollback_manifest.json" else "patch"
        if not _is_trusted_patch_audit(path, value, loaded):
            diagnostics["invalid_records"] += 1
            diagnostics["skipped_files"].append(
                {
                    "path": str(path),
                    "error": "ignored untrusted or incomplete binary patch audit manifest",
                }
            )
            continue
        item = artifacts.setdefault(
            (path.parent.resolve(), audit_type),
            {"timestamp": "", "audit_type": audit_type},
        )
        item["artifact_path"] = str(path.parent)
        if path.name == "rollback_manifest.json":
            item["rollback_manifest_path"] = str(path)
            fields = {
                "patched_path": "source_path",
                "restored_path": "patched_path",
                "patched_sha256": "source_sha256",
                "restored_sha256": "patched_sha256",
                "status": "status",
                "dry_run": "dry_run",
            }
        else:
            item["manifest_path" if path.name == "patch_manifest.json" else "rollback_path"] = str(path)
            fields = {
                "source_path": "source_path",
                "patched_path": "patched_path",
                "source_sha256": "source_sha256",
                "patched_sha256": "patched_sha256",
                "status": "status",
                "dry_run": "dry_run",
            }
        for key, normalized_key in fields.items():
            if key in value and value[key] is not None:
                item[normalized_key] = value[key]
        if isinstance(value.get("operations"), list) and (
            path.name != "rollback.json" or "operation_count" not in item
        ):
            item["operation_count"] = len(value["operations"])
        timestamp = _record_timestamp(value)
        if timestamp:
            item["timestamp"] = timestamp
        elif not item["timestamp"]:
            try:
                item["timestamp"] = datetime.fromtimestamp(
                    path.stat().st_mtime, tz=timezone.utc
                ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            except OSError:
                pass

    recent: list[dict[str, Any]] = []
    for item in artifacts.values():
        status = str(item.get("status") or ("planned" if item.get("dry_run") else "unknown"))
        recent.append(
            {
                "source_path": _audit_text(item.get("source_path")),
                "patched_path": _audit_text(item.get("patched_path")),
                "source_sha256": _audit_text(item.get("source_sha256")),
                "patched_sha256": _audit_text(item.get("patched_sha256")),
                "operation_count": _audit_count(item.get("operation_count")),
                "timestamp": _audit_text(item.get("timestamp")),
                "status": status,
                "dry_run": bool(item.get("dry_run")),
                "artifact_path": _audit_text(item.get("artifact_path")),
                "audit_type": _audit_text(item.get("audit_type")) or "patch",
            }
        )
    recent.sort(key=lambda item: item["timestamp"], reverse=True)
    return {
        "count": len(recent),
        "dry_run_count": sum(item["dry_run"] for item in recent),
        "applied_count": sum(not item["dry_run"] and item["status"].lower() == "ok" for item in recent),
        "recent": recent[:20],
    }


def _load_evidence_manifests(workspace: Path, diagnostics: dict[str, Any]) -> dict[str, Any]:
    """Verify discovered evidence packages before exposing their status in UI.

    Dashboard data must not treat a file merely named ``evidence-manifest.json``
    as trusted. Each candidate is parsed and verified through the same path and
    hash checks exposed by the CLI. Invalid packages remain visible as failed
    audit rows rather than being mistaken for successful analysis evidence.
    """

    try:
        paths = sorted(workspace.rglob("evidence-manifest.json"), key=lambda path: str(path))
    except OSError:
        paths = []

    rows: list[dict[str, Any]] = []
    for path in paths:
        payload = _load_json(path, diagnostics)
        if not isinstance(payload, dict):
            if payload is not None:
                diagnostics["invalid_records"] += 1
            continue
        try:
            from .evidence import EVIDENCE_MANIFEST_SCHEMA, verify_manifest

            verification = verify_manifest(path)
        except Exception as error:  # noqa: BLE001 - dashboard remains usable without optional data
            verification = {
                "status": "failed",
                "valid": False,
                "verified_file_count": 0,
                "unavailable_stage_count": 0,
                "issues": [{"kind": "verification_error", "detail": f"{type(error).__name__}: {error}"}],
            }
            EVIDENCE_MANIFEST_SCHEMA = "reverse_analyzer.evidence_manifest/v1"

        artifacts = payload.get("artifacts")
        artifact_count = len(artifacts) if isinstance(artifacts, list) else 0
        covered_file_count = sum(
            1
            for item in artifacts or []
            if isinstance(item, dict)
            and item.get("sha256")
            and str(item.get("status") or "ok").lower()
            in {"ok", "succeeded", "success", "available", "complete", "completed"}
        )
        issues = verification.get("issues") if isinstance(verification.get("issues"), list) else []
        try:
            relative_path = path.resolve().relative_to(workspace.resolve()).as_posix()
        except ValueError:
            relative_path = str(path)
        rows.append(
            {
                "manifest_path": relative_path,
                "manifest_id": payload.get("manifest_id"),
                "schema": payload.get("schema"),
                "schema_valid": payload.get("schema") == EVIDENCE_MANIFEST_SCHEMA,
                "status": "ok" if verification.get("valid") else "failed",
                "artifact_count": artifact_count,
                "covered_file_count": covered_file_count,
                "verified_file_count": _audit_count(verification.get("verified_file_count")),
                "unavailable_stage_count": _audit_count(verification.get("unavailable_stage_count")),
                "issue_count": len(issues),
                "issue_kinds": sorted(
                    {str(item.get("kind") or "unknown") for item in issues if isinstance(item, dict)}
                ),
            }
        )

    rows.sort(key=lambda item: (item["status"] != "failed", item["manifest_path"]))
    return {
        "count": len(rows),
        "valid_count": sum(1 for item in rows if item["status"] == "ok"),
        "failed_count": sum(1 for item in rows if item["status"] != "ok"),
        "covered_file_count": sum(int(item["covered_file_count"]) for item in rows),
        "verified_file_count": sum(int(item["verified_file_count"]) for item in rows),
        "recent": rows[:50],
    }


def _is_trusted_patch_audit(
    path: Path,
    payload: dict[str, Any],
    loaded: dict[Path, dict[str, Any]],
) -> bool:
    """Accept only schema-valid patch outputs, never filename-only matches."""

    if path.name == "patch_manifest.json":
        if not _is_patch_apply_manifest(payload):
            return False
        # The normal CLI location is explicit.  A caller may also select a
        # custom artifact directory, in which case the paired rollback plan
        # supplies the association proof.
        if path.parent.name.endswith(".patch-artifacts"):
            return True
        return _is_matching_rollback_plan(payload, loaded.get(path.parent / "rollback.json"))
    if path.name == "rollback_manifest.json":
        return _is_patch_rollback_manifest(payload)
    return False


def _is_patch_apply_manifest(payload: dict[str, Any]) -> bool:
    return (
        _has_schema_v1(payload)
        and _has_text_fields(payload, "source_path", "patched_path")
        and _has_sha256_fields(payload, "source_sha256", "patched_sha256")
        and _has_audit_state(payload)
        and isinstance(payload.get("operations"), list)
    )


def _is_patch_rollback_manifest(payload: dict[str, Any]) -> bool:
    return (
        _has_schema_v1(payload)
        and _has_text_fields(payload, "patched_path", "restored_path")
        and _has_sha256_fields(payload, "patched_sha256", "restored_sha256")
        and _has_audit_state(payload)
        and isinstance(payload.get("operations"), list)
    )


def _is_matching_rollback_plan(
    manifest: dict[str, Any],
    rollback: dict[str, Any] | None,
) -> bool:
    if not isinstance(rollback, dict):
        return False
    if not _has_schema_v1(rollback) or not _has_text_fields(rollback, "source_path"):
        return False
    if not _has_sha256_fields(rollback, "source_sha256", "patched_sha256"):
        return False
    if not isinstance(rollback.get("operations"), list):
        return False
    return (
        rollback.get("source_path") == manifest.get("source_path")
        and rollback.get("source_sha256") == manifest.get("source_sha256")
        and rollback.get("patched_sha256") == manifest.get("patched_sha256")
    )


def _has_schema_v1(payload: dict[str, Any]) -> bool:
    return payload.get("schema_version") == 1 and not isinstance(payload.get("schema_version"), bool)


def _has_text_fields(payload: dict[str, Any], *names: str) -> bool:
    return all(isinstance(payload.get(name), str) and bool(payload[name].strip()) for name in names)


def _has_sha256_fields(payload: dict[str, Any], *names: str) -> bool:
    return all(
        isinstance(payload.get(name), str)
        and len(payload[name]) == 64
        and all(character in "0123456789abcdefABCDEF" for character in payload[name])
        for name in names
    )


def _has_audit_state(payload: dict[str, Any]) -> bool:
    return (
        isinstance(payload.get("dry_run"), bool)
        and isinstance(payload.get("status"), str)
        and payload["status"].lower() in {"ok", "planned"}
    )


def _audit_text(value: Any) -> str | None:
    """Return bounded scalar audit data; manifests must not expand dashboard data."""

    if value is None:
        return None
    return str(value)[:2048]


def _audit_count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _recommend_dynamic_profile(data: Any) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    profiles = data.get("profiles", {}) if isinstance(data, dict) else {}
    if not isinstance(profiles, dict):
        profiles = {}
    for name, value in profiles.items():
        if not isinstance(value, dict):
            continue
        record = dict(value)
        runs = max(1, int(_number(record.get("runs"))))
        score = (
            _number(record.get("success_rate")) * 10
            + _number(record.get("avg_events")) * 0.1
            - _number(record.get("avg_planned_hooks")) * 0.02
            + min(2.0, runs * 0.1)
        )
        record.update(profile=str(record.get("profile") or name), score=round(score, 3))
        candidates.append(record)
    if not candidates:
        return {"profile": "quick", "score": 0.0, "reason": "no dynamic profile history"}
    candidates.sort(key=lambda item: (-_number(item.get("score")), -_number(item.get("runs")), str(item["profile"])))
    best = candidates[0]
    return {key: best[key] for key in ("profile", "score", "runs", "success_rate", "avg_events", "avg_planned_hooks") if key in best}


def _recommend_gui_strategy(data: Any) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    strategies = data.get("strategies", {}) if isinstance(data, dict) else {}
    if not isinstance(strategies, dict):
        strategies = {}
    for key, value in strategies.items():
        if not isinstance(value, dict):
            continue
        record = dict(value)
        runs = max(1, int(_number(record.get("runs"))))
        framework = str(record.get("framework") or str(key).split(":", 1)[0] or "unknown")
        strategy = str(record.get("strategy") or str(key).split(":", 1)[-1])
        score = (
            _number(record.get("success_rate")) * 10
            + _number(record.get("avg_visual_similarity")) * 5
            + _number(record.get("avg_control_match_rate")) * 2
            + _number(record.get("avg_text_match_rate")) * 2
            + min(2.0, runs * 0.1)
        )
        record.update(framework=framework, strategy=strategy, score=round(score, 3))
        candidates.append(record)
    if not candidates:
        return {
            "framework": None,
            "strategy": "manual_assisted_visual_reconstruction",
            "score": 0.0,
            "reason": "no GUI strategy history",
        }
    candidates.sort(key=lambda item: (-_number(item.get("score")), -_number(item.get("runs")), item["framework"], item["strategy"]))
    best = candidates[0]
    keys = ("framework", "strategy", "score", "runs", "success_rate", "avg_visual_similarity", "avg_control_match_rate", "avg_text_match_rate")
    return {key: best[key] for key in keys if key in best}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def _embedded_json(data: dict[str, Any]) -> str:
    """Encode JSON safely for an HTML script element, including ``</script>``."""

    return json.dumps(data, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _html_document(data: dict[str, Any]) -> str:
    payload = _embedded_json(data)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reverse Lab Command Deck</title>
  <style>
    :root {{ color-scheme: dark; --ink:#edf4f2; --muted:#8ca19c; --line:#29403d; --panel:#101b1a; --base:#07100f; --accent:#56d8ae; --amber:#f8bf56; --red:#ef7373; }}
    * {{ box-sizing:border-box; }} body {{ margin:0; background:var(--base); color:var(--ink); font:14px/1.45 ui-monospace,Consolas,monospace; }}
    header {{ padding:28px max(24px, calc((100vw - 1280px)/2)); border-bottom:1px solid var(--line); background:#0a1513; }}
    h1 {{ margin:0; font-size:24px; letter-spacing:0; }} .eyebrow {{ color:var(--accent); font-size:11px; text-transform:uppercase; margin-bottom:7px; }}
    main {{ max-width:1280px; margin:auto; padding:24px; }} .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:24px; }}
    .kpi,.panel {{ border:1px solid var(--line); background:var(--panel); border-radius:4px; }} .kpi {{ padding:15px; }} .kpi b {{ display:block; color:var(--accent); font-size:26px; margin-top:4px; }}
    .grid {{ display:grid; grid-template-columns:1.25fr .75fr; gap:16px; }} .panel {{ padding:18px; margin-bottom:16px; }} h2 {{ font-size:14px; margin:0 0 14px; color:#c9d8d4; text-transform:uppercase; }}
    .toolbar {{ display:flex; gap:10px; margin-bottom:12px; }} input,select {{ color:var(--ink); background:#0a1413; border:1px solid var(--line); padding:9px; border-radius:3px; font:inherit; }} input {{ flex:1; min-width:0; }}
    table {{ width:100%; border-collapse:collapse; }} th,td {{ padding:10px 7px; border-top:1px solid #1d302e; text-align:left; vertical-align:top; }} th {{ color:var(--muted); font-size:11px; text-transform:uppercase; }}
    .badge {{ display:inline-block; padding:2px 7px; border:1px solid var(--line); border-radius:2px; color:var(--amber); }} .recommendation {{ border-left:3px solid var(--accent); padding-left:12px; margin:14px 0; }}
    .empty {{ color:var(--muted); padding:20px 0; text-align:center; }} .meta {{ color:var(--muted); font-size:12px; }} ul {{ margin:0; padding-left:18px; }}
    .source-panel {{ margin-top:16px; }} .source-summary {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px; color:var(--muted); }} .source-project {{ border-top:1px solid #1d302e; padding:14px 0; }} .source-project:first-child {{ border-top:0; padding-top:0; }} .source-head {{ display:flex; justify-content:space-between; gap:12px; align-items:baseline; }} .source-head strong {{ color:var(--accent); }} .source-metrics {{ display:flex; flex-wrap:wrap; gap:10px; margin:8px 0; color:var(--muted); font-size:12px; }} details {{ margin-top:9px; }} summary {{ cursor:pointer; color:#c9d8d4; }} .source-files {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:8px; margin-top:10px; }} .source-file {{ border:1px solid #1d302e; background:#0a1413; padding:9px; border-radius:3px; }} pre {{ white-space:pre-wrap; overflow-wrap:anywhere; max-height:180px; overflow:auto; margin:8px 0 0; padding:8px; border-left:2px solid #29403d; color:#c9d8d4; }}
    @media (max-width:780px) {{ .kpis {{ grid-template-columns:repeat(2,1fr); }} .grid {{ grid-template-columns:1fr; }} .toolbar {{ flex-direction:column; }} table {{ font-size:12px; }} }}
  </style>
</head>
<body>
  <header><div class="eyebrow">Offline reverse engineering operations</div><h1>Reverse Lab Command Deck</h1></header>
  <main>
    <section class="kpis" id="kpis"></section>
    <section class="grid">
      <div class="panel"><h2>Experiment Queue</h2><div class="toolbar"><input id="search" aria-label="Search experiments" placeholder="Search targets, IDs, notes"><select id="status" aria-label="Filter experiment status"><option value="">All statuses</option></select></div><div id="experiments"></div></div>
      <aside><div class="panel"><h2>Recommended Profiles</h2><div id="recommendations"></div></div><div class="panel"><h2>Recent Sessions</h2><div id="sessions"></div></div><div class="panel"><h2>Ingestion Diagnostics</h2><div id="diagnostics"></div></div></aside>
    </section>
    <section class="panel"><h2>Platform Core</h2><div id="platform-core"></div></section>
    <section class="panel"><h2>Binary Patch Audit</h2><div id="binary-patches"></div></section>
    <section class="panel"><h2>Evidence Integrity</h2><div id="evidence-manifests"></div></section>
    <section class="panel source-panel"><h2>Source Reconstruction</h2><div id="source-reconstruction"></div></section>
  </main>
  <script id="dashboard-data" type="application/json">{payload}</script>
  <script>
    (() => {{
      const data = JSON.parse(document.getElementById('dashboard-data').textContent);
      const el = id => document.getElementById(id);
      const text = value => value == null || value === '' ? '---' : String(value);
      const summary = data.summary;
      const reconstruction = data.source_reconstruction || {{summary: {{}}, projects: []}};
      const reconstructionSummary = reconstruction.summary || {{}};
      const patches = data.binary_patches || {{count: 0, dry_run_count: 0, applied_count: 0, recent: []}};
      const evidence = data.evidence_manifests || {{count: 0, valid_count: 0, failed_count: 0, recent: []}};
      const platformCore = data.platform_core || {{status: "unavailable", cards: [], capabilities: {{}}, artifacts: {{}}}};
      const kpis = [['Experiments', summary.experiment_total], ['Completed', summary.completed_total], ['Sessions', summary.session_total], ['Verified evidence', evidence.valid_count || 0], ['Applied patches', patches.applied_count || 0], ['Source projects', reconstructionSummary.project_total || 0], ['Data warnings', data.diagnostics.malformed_json], ['Platform core', platformCore.status || 'unavailable']];
      kpis.forEach(([label,value]) => {{ const card=document.createElement('div'); card.className='kpi'; const small=document.createElement('span'); small.textContent=label; const bold=document.createElement('b'); bold.textContent=value; card.append(small,bold); el('kpis').append(card); }});
      const statuses = Object.keys(summary.status_counts).sort(); statuses.forEach(status => {{ const option=document.createElement('option'); option.value=status; option.textContent=status; el('status').append(option); }});
      function renderExperiments() {{
        const needle=el('search').value.toLowerCase(), status=el('status').value;
        const rows=data.experiments.filter(item => {{ const corpus=JSON.stringify(item).toLowerCase(); return (!needle || corpus.includes(needle)) && (!status || String(item.status || 'unknown').toLowerCase() === status); }});
        const box=el('experiments'); box.replaceChildren();
        if (!rows.length) {{ const empty=document.createElement('div'); empty.className='empty'; empty.textContent='No experiments match the current view.'; box.append(empty); return; }}
        const table=document.createElement('table'), head=document.createElement('tr'); ['Experiment','Target','Status','Updated'].forEach(label => {{ const th=document.createElement('th'); th.textContent=label; head.append(th); }}); const thead=document.createElement('thead'); thead.append(head); const body=document.createElement('tbody');
        rows.forEach(item => {{ const tr=document.createElement('tr'); const values=[item.name || item.id || item.experiment_id || item.source_file, item.target || item.sample_id || item.path, item.status || 'unknown', item.updated_at || item.timestamp || item.created_at]; values.forEach((value,index) => {{ const td=document.createElement('td'); if(index===2) {{ const badge=document.createElement('span'); badge.className='badge'; badge.textContent=text(value); td.append(badge); }} else td.textContent=text(value); tr.append(td); }}); body.append(tr); }}); table.append(thead,body); box.append(table);
      }}
      function recommendation(title, value) {{ const box=document.createElement('div'); box.className='recommendation'; const name=document.createElement('strong'); name.textContent=title; const detail=document.createElement('div'); detail.className='meta'; detail.textContent=Object.entries(value).filter(([key]) => key !== 'reason').map(([key,val]) => key + ': ' + text(val)).join(' | ') || text(value.reason); box.append(name,detail); return box; }}
      el('recommendations').append(recommendation('Dynamic profile', data.recommendations.dynamic_profile), recommendation('GUI strategy', data.recommendations.gui_strategy));
      const sessions=el('sessions'); if (!data.sessions.length) {{ sessions.innerHTML='<div class="empty">No sessions recorded.</div>'; }} else {{ const list=document.createElement('ul'); data.sessions.forEach(item => {{ const line=document.createElement('li'); line.textContent=[item.session_id || item.id || item.target || item.source_file, item.status || 'unknown', item.updated_at || item.timestamp || item.created_at].filter(Boolean).join(' | '); list.append(line); }}); sessions.append(list); }}
      const diagnostics=el('diagnostics'); diagnostics.textContent='Loaded ' + data.diagnostics.files_loaded + '/' + data.diagnostics.files_scanned + ' JSON files; malformed: ' + data.diagnostics.malformed_json + '; invalid records: ' + data.diagnostics.invalid_records + '.';

      const platformBox=el('platform-core');
      const platformCards=Array.isArray(platformCore.cards) ? platformCore.cards : [];
      if (!platformCards.length) {{ const empty=document.createElement('div'); empty.className='empty'; empty.textContent='No platform core report found yet.'; platformBox.append(empty); }} else {{
        const summary=document.createElement('div'); summary.className='source-summary'; summary.append('Status: ' + text(platformCore.status)); platformBox.append(summary);
        const cardRow=document.createElement('div'); cardRow.className='kpis'; platformCards.forEach(item => {{ const card=document.createElement('div'); card.className='kpi'; const small=document.createElement('span'); small.textContent=text(item.title); const bold=document.createElement('b'); bold.textContent=text(item.value); const sub=document.createElement('div'); sub.className='meta'; sub.textContent=text(item.subtitle); card.append(small,bold,sub); cardRow.append(card); }}); platformBox.append(cardRow);
        const caps=document.createElement('div'); caps.className='meta'; caps.textContent='Capabilities: ' + Object.entries(platformCore.capabilities || {{}}).map(([key, providers]) => key + ' (' + (providers || []).join(', ') + ')').join(' | '); platformBox.append(caps);
        const artifacts=document.createElement('div'); artifacts.className='meta'; artifacts.textContent='Artifacts: semantic_ir=' + text((platformCore.artifacts || {{}}).semantic_ir) + ' | evidence_graph=' + text((platformCore.artifacts || {{}}).evidence_graph); platformBox.append(artifacts);
        const audit=platformCore.capability_audit || {{record_count: 0, records: [], summary: {{}}}};
        const auditSummary=audit.summary || {{}};
        const auditMeta=document.createElement('div'); auditMeta.className='meta';
        const statusCounts=Object.entries(auditSummary.status_counts || {{}}).map(([key, value]) => key + '=' + text(value)).join(', ');
        auditMeta.textContent='Capability audit: records=' + text(audit.record_count || 0) + ' | rollback=' + text(auditSummary.rollback_supported_count || 0) + ' | manifests=' + text(auditSummary.manifest_reference_count || 0) + ' | traces=' + text(auditSummary.dashboard_trace_count || 0) + (statusCounts ? ' | statuses=' + statusCounts : '');
        platformBox.append(auditMeta);
        const auditRows=Array.isArray(audit.records) ? audit.records : [];
        if (auditRows.length) {{
          const details=document.createElement('details');
          const caption=document.createElement('summary');
          caption.textContent='Capability audit records (' + auditRows.length + ')';
          details.append(caption);
          const list=document.createElement('ul');
          auditRows.slice(0, 12).forEach(item => {{
            const target=item.target_identity || {{}};
            const line=document.createElement('li');
            line.textContent=[
              text(item.capability) + ':' + text(item.action),
              'provider=' + text(item.provider),
              'status=' + text(item.status),
              'target=' + text(target.display_name || target.path || target.pid || target.kind)
            ].join(' | ');
            list.append(line);
          }});
          details.append(list);
          platformBox.append(details);
        }}
      }}
      const patchBox=el('binary-patches'); const patchRows=Array.isArray(patches.recent) ? patches.recent : [];
      if (!patchRows.length) {{ const empty=document.createElement('div'); empty.className='empty'; empty.textContent='No binary patch manifests found in sessions or output artifacts.'; patchBox.append(empty); }} else {{
        const summary=document.createElement('div'); summary.className='meta'; summary.textContent='Audited: ' + text(patches.count) + ' | applied: ' + text(patches.applied_count) + ' | dry runs: ' + text(patches.dry_run_count); patchBox.append(summary);
        const table=document.createElement('table'), head=document.createElement('tr'); ['Action','Input ? output','Hashes','Operations','Status','Timestamp'].forEach(label => {{ const th=document.createElement('th'); th.textContent=label; head.append(th); }}); const thead=document.createElement('thead'); thead.append(head); const body=document.createElement('tbody');
        patchRows.forEach(item => {{ const tr=document.createElement('tr'); const values=[item.audit_type || 'patch', [text(item.source_path), text(item.patched_path)].join(' ? '), [text(item.source_sha256), text(item.patched_sha256)].join(' ? '), item.operation_count, item.dry_run ? 'dry run' : (item.status || 'unknown'), item.timestamp]; values.forEach((value,index) => {{ const td=document.createElement('td'); if(index===0 || index===4) {{ const badge=document.createElement('span'); badge.className='badge'; badge.textContent=text(value); td.append(badge); }} else td.textContent=text(value); tr.append(td); }}); body.append(tr); }}); table.append(thead,body); patchBox.append(table);
      }}
      const evidenceBox=el('evidence-manifests'); const evidenceRows=Array.isArray(evidence.recent) ? evidence.recent : [];
      if (!evidenceRows.length) {{ const empty=document.createElement('div'); empty.className='empty'; empty.textContent='No evidence manifests found. Run analyze to create a portable verification package.'; evidenceBox.append(empty); }} else {{
        const summary=document.createElement('div'); summary.className='meta'; summary.textContent='Packages: ' + text(evidence.count) + ' | valid: ' + text(evidence.valid_count) + ' | failed: ' + text(evidence.failed_count) + ' | verified files: ' + text(evidence.verified_file_count); evidenceBox.append(summary);
        const table=document.createElement('table'), head=document.createElement('tr'); ['Manifest','Status','Files','Unavailable','Issues'].forEach(label => {{ const th=document.createElement('th'); th.textContent=label; head.append(th); }}); const thead=document.createElement('thead'); thead.append(head); const body=document.createElement('tbody');
        evidenceRows.forEach(item => {{ const tr=document.createElement('tr'); const values=[item.manifest_path, item.status || 'unknown', text(item.verified_file_count) + '/' + text(item.covered_file_count), item.unavailable_stage_count, item.issue_count ? item.issue_count + ' (' + (item.issue_kinds || []).join(', ') + ')' : '0']; values.forEach((value,index) => {{ const td=document.createElement('td'); if(index===1) {{ const badge=document.createElement('span'); badge.className='badge'; badge.textContent=text(value); td.append(badge); }} else td.textContent=text(value); tr.append(td); }}); body.append(tr); }}); table.append(thead,body); evidenceBox.append(table);
      }}
      const reconstructionBox=el('source-reconstruction');
      const projects=Array.isArray(reconstruction.projects) ? reconstruction.projects : [];
      if (!projects.length) {{ const empty=document.createElement('div'); empty.className='empty'; empty.textContent='No reconstructed source projects discovered yet. Run analyze with --reconstruct or --reconstruct-gui.'; reconstructionBox.append(empty); }} else {{
        const sourceSummary=document.createElement('div'); sourceSummary.className='source-summary';
        [['Projects', reconstructionSummary.project_total], ['Source files', reconstructionSummary.source_file_total], ['Resources', reconstructionSummary.resource_file_total], ['Recovered functions', reconstructionSummary.function_total], ['Dynamic evidence', reconstructionSummary.dynamic_evidence_total], ['Semantic entities', reconstructionSummary.semantic_entity_total], ['Verified projects', reconstructionSummary.verified_project_total]].forEach(([label,value]) => {{ const item=document.createElement('span'); item.textContent=label + ': ' + text(value || 0); sourceSummary.append(item); }});
        reconstructionBox.append(sourceSummary);
        projects.forEach(project => {{
          const card=document.createElement('article'); card.className='source-project';
          const head=document.createElement('div'); head.className='source-head'; const name=document.createElement('strong'); name.textContent=text(project.name || project.relative_path || 'reconstructed project'); const state=document.createElement('span'); state.className='badge'; state.textContent=text(project.status || project.output_stack || project.language || 'discovered'); head.append(name,state); card.append(head);
          const location=document.createElement('div'); location.className='meta'; location.textContent=text(project.relative_path || project.project_dir || project.path); card.append(location);
          const metrics=document.createElement('div'); metrics.className='source-metrics'; [['Language', project.language || project.output_stack], ['Source files', project.source_file_count], ['Resources', project.resource_file_count], ['Functions', project.function_count], ['Modules', project.module_count], ['Evidence', project.dynamic_evidence_count], ['Semantic', project.semantic_entity_count], ['Verify', project.verification_score], ['Next', project.next_task]].forEach(([label,value]) => {{ if(value != null && value !== '') {{ const item=document.createElement('span'); item.textContent=label + ': ' + text(value); metrics.append(item); }} }}); card.append(metrics);
          const files=Array.isArray(project.source_files) ? project.source_files : [];
          if (files.length) {{ const details=document.createElement('details'); const caption=document.createElement('summary'); caption.textContent='Recovered source files (' + files.length + ')'; details.append(caption); const fileGrid=document.createElement('div'); fileGrid.className='source-files'; files.slice(0, 24).forEach(file => {{ const item=document.createElement('div'); item.className='source-file'; const path=document.createElement('strong'); path.textContent=text(file.path || file.relative_path || file.name); const info=document.createElement('div'); info.className='meta'; info.textContent=[file.language, file.size_bytes != null ? file.size_bytes + ' B' : null].filter(Boolean).join(' | '); item.append(path,info); if(file.preview) {{ const preview=document.createElement('pre'); preview.textContent=text(file.preview); item.append(preview); }} fileGrid.append(item); }}); details.append(fileGrid); card.append(details); }}
          reconstructionBox.append(card);
        }});
      }}
      el('search').addEventListener('input', renderExperiments); el('status').addEventListener('change', renderExperiments); renderExperiments();
    }})();
  </script>
</body>
</html>
"""
