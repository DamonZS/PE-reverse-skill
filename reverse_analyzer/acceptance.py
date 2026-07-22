"""Persistent, hash-backed acceptance records for registered live fixtures.

The runner intentionally accepts a fixture identifier instead of a command.
Commands are immutable structured argv values from the repository registry and
are always executed with ``shell=False``.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .environment_validation import (
    acceptance_fixture_definitions,
    validate_external_environment,
    write_environment_report,
)


Runner = Callable[..., subprocess.CompletedProcess[str]]
_LIVE_EVIDENCE_LEVELS = {"live-target", "live-child-process", "interactive-live-target"}
_SUCCESS_VALUES = {"ok", "passed", "success", "succeeded", "restored", "rolled_back", "stopped", "unloaded"}


class AcceptanceError(ValueError):
    """Raised when an acceptance request violates the registered contract."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_hash(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(dict(value), ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _fixture_map() -> dict[str, dict[str, Any]]:
    return {str(item["id"]): dict(item) for item in acceptance_fixture_definitions()}


def _safe_workspace(workspace: str | Path) -> Path:
    root = Path(workspace).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    if not root.is_dir():
        raise AcceptanceError(f"acceptance workspace is not a directory: {root}")
    return root


def _safe_relative_pattern(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    if not text or Path(text).is_absolute() or ":" in text.split("/", 1)[0]:
        raise AcceptanceError(f"invalid acceptance artifact path: {value!r}")
    parts = [part for part in text.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise AcceptanceError(f"acceptance artifact escapes the run directory: {value!r}")
    return "/".join(parts)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _registered_argv(fixture: Mapping[str, Any]) -> list[str]:
    raw = fixture.get("argv")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)) or not raw:
        raise AcceptanceError(f"fixture {fixture.get('id')} has no structured argv contract")
    argv = [str(item) for item in raw]
    if argv[0] != "{python}":
        raise AcceptanceError(f"fixture {fixture.get('id')} uses an unapproved executable")
    argv[0] = sys.executable
    if any(not item or "\x00" in item for item in argv):
        raise AcceptanceError(f"fixture {fixture.get('id')} contains an invalid argv item")
    return argv


def _target_identity_valid(identity: Mapping[str, Any] | None) -> bool:
    if not isinstance(identity, Mapping) or not identity:
        return False
    return any(
        str(identity.get(key) or "").strip()
        for key in ("pid", "path", "sha256", "sample_sha256", "bundle_id", "package_name")
    )


def _fixture_target_identity_valid(
    identity: Mapping[str, Any] | None,
    *,
    fixture_id: str,
) -> bool:
    """Apply identity fields required by a registered live fixture.

    Frida's configured selector (for example ``usb``) is not evidence of the
    device that actually ran.  Retained P5 records must include the observed
    device identity alongside the package name so a later verifier can bind
    the record to a concrete device session.
    """

    if not _target_identity_valid(identity):
        return False
    if fixture_id != "p5-android-frida-live":
        return True
    return all(str(identity.get(key) or "").strip() for key in (
        "package_name",
        "device_id",
        "device_name",
        "device_type",
    ))


def _load_target_identity(run_dir: Path, fixture: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    raw = fixture.get("target_identity_artifact")
    if not raw:
        return {}, None
    pattern = _safe_relative_pattern(raw)
    matches = sorted(path.resolve() for path in run_dir.glob(pattern) if path.is_file())
    matches = [path for path in matches if _inside(path, run_dir)]
    if len(matches) != 1:
        return {}, pattern
    try:
        payload = json.loads(matches[0].read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}, pattern
    return (dict(payload), None) if isinstance(payload, Mapping) else ({}, pattern)


def _load_json_artifact(
    run_dir: Path,
    raw_path: Any,
) -> tuple[dict[str, Any], str | None, Path | None]:
    """Load one registered JSON artifact without allowing path ambiguity."""

    if not raw_path:
        return {}, None, None
    pattern = _safe_relative_pattern(raw_path)
    matches = sorted(path.resolve() for path in run_dir.glob(pattern) if path.is_file())
    matches = [path for path in matches if _inside(path, run_dir)]
    if len(matches) != 1:
        return {}, pattern, None
    try:
        payload = json.loads(matches[0].read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}, pattern, matches[0]
    return (dict(payload), None, matches[0]) if isinstance(payload, Mapping) else ({}, pattern, matches[0])


def _execution_proof_valid(
    proof: Mapping[str, Any] | None,
    *,
    required_executed_tests: int = 1,
) -> tuple[bool, list[str]]:
    """Require structured evidence that a live fixture actually executed."""

    errors: list[str] = []
    if not isinstance(proof, Mapping) or not proof:
        return False, ["execution proof is missing or invalid"]
    status = str(proof.get("status") or "").strip().lower()
    if status not in _SUCCESS_VALUES:
        errors.append("execution proof status is not successful")
    for key in ("executed_tests", "skipped_tests", "live_operations"):
        value = proof.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"execution proof {key} must be a non-negative integer")
    executed_tests = proof.get("executed_tests")
    if isinstance(executed_tests, int) and executed_tests < required_executed_tests:
        errors.append(
            "execution proof executed_tests is below the fixture requirement "
            f"({executed_tests} < {required_executed_tests})"
        )
    if isinstance(proof.get("skipped_tests"), int) and proof.get("skipped_tests") != 0:
        errors.append("execution proof contains skipped tests")
    if isinstance(proof.get("live_operations"), int) and proof.get("live_operations", 0) <= 0:
        errors.append("execution proof contains no live operations")
    if _contains_synthetic_provenance(proof):
        errors.append("execution proof contains synthetic provenance")
    return not errors, errors


def _target_identities_match(
    requested: Mapping[str, Any] | None,
    observed: Mapping[str, Any] | None,
) -> bool:
    if not requested or not observed:
        return True
    keys = ("pid", "path", "sha256", "sample_sha256", "bundle_id", "package_name")
    compared = False
    for key in keys:
        left = requested.get(key)
        right = observed.get(key)
        if left in (None, "") or right in (None, ""):
            continue
        compared = True
        if str(left).strip().lower() != str(right).strip().lower():
            return False
    return compared


def _contains_synthetic_provenance(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in {"synthetic", "mock", "simulated"} and item is True:
                return True
            if lowered in {"provider", "provider_kind", "evidence_class", "provenance"} and not isinstance(
                item, (Mapping, list)
            ):
                text = str(item).lower()
                if any(marker in text for marker in ("synthetic", "mock", "simulated")):
                    return True
            if _contains_synthetic_provenance(item):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_synthetic_provenance(item) for item in value)
    return False


def _artifact_provenance_valid(paths: Sequence[Path]) -> tuple[bool, list[str]]:
    rejected: list[str] = []
    for path in paths:
        if path.suffix.lower() != ".json":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if _contains_synthetic_provenance(payload):
            rejected.append(path.as_posix())
    return not rejected, rejected


def _proof_ok(paths: Sequence[Path], *, required: bool) -> dict[str, Any]:
    if not required:
        return {"status": "not_required", "verified": True, "artifacts": []}
    inspected: list[str] = []
    for path in paths:
        inspected.append(path.as_posix())
        if not path.is_file() or path.suffix.lower() != ".json":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, Mapping):
            continue
        status = str(payload.get("status") or payload.get("outcome") or "").lower()
        explicit = any(
            payload.get(key) is True
            for key in ("verified", "restored", "rollback_verified", "cleanup_verified", "detached", "unloaded")
        )
        if status in _SUCCESS_VALUES or explicit:
            return {"status": "ok", "verified": True, "artifacts": inspected}
    return {"status": "missing_or_unverified", "verified": False, "artifacts": inspected}


def _fixture_proof_ok(
    paths: Sequence[Path],
    *,
    required: bool,
    fixture_id: str,
    role: str,
) -> dict[str, Any]:
    """Validate semantic rollback/cleanup evidence for a registered fixture.

    A generic ``status: ok`` is useful for repository tooling, but it is not
    sufficient evidence for a live promotion.  The Android fixtures must
    prove restoration/detach, while the protocol fixture must prove both
    capture and replay sessions were closed.
    """

    result = _proof_ok(paths, required=required)
    if not result.get("verified") or not required:
        return result
    payload: Mapping[str, Any] | None = None
    for path in paths:
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(loaded, Mapping):
            payload = loaded
            break
    if payload is None:
        return {
            **result,
            "status": "missing_or_unverified",
            "verified": False,
            "error": "proof artifact is not a JSON object",
        }

    semantic_ok = True
    reason = ""
    if fixture_id == "p6-protocol-runtime-loopback" and role == "cleanup":
        # The fixture runs two independent provider sessions.  Requiring both
        # nested rollback results prevents one closed socket from standing in
        # for the complete capture -> replay lifecycle.
        if payload.get("verified") is not True:
            semantic_ok = False
            reason = "protocol rollback proof is not verified"
        else:
            for name in ("capture", "replay"):
                child = payload.get(name)
                if not isinstance(child, Mapping) or child.get("ok") is not True:
                    semantic_ok = False
                    reason = f"protocol rollback proof lacks successful {name} session"
                    break
    elif fixture_id in {
        "p5-android-rebuild-sign-live",
        "p5-android-native-patch-live",
    } and role == "rollback":
        if payload.get("restored") is not True or payload.get("verified") is not True:
            semantic_ok = False
            reason = "Android rollback proof must verify restoration"
        if fixture_id == "p5-android-native-patch-live" and payload.get(
            "device_cleanup_verified"
        ) is not True:
            semantic_ok = False
            reason = "native APK rollback proof must verify device cleanup"
    elif fixture_id == "p5-android-frida-live" and role == "cleanup":
        if not (
            (payload.get("cleanup_verified") is True or payload.get("verified") is True)
            and payload.get("detached") is True
            and payload.get("unloaded") is True
        ):
            semantic_ok = False
            reason = "Frida cleanup proof must verify unload and detach"
    if not semantic_ok:
        return {**result, "status": "missing_or_unverified", "verified": False, "error": reason}
    return result


def _environment_fixture_state(run_dir: Path, fixture_id: str) -> dict[str, Any] | None:
    """Read the retained environment report for one registered fixture."""
    report_path = run_dir / "environment-validation.json"
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping):
        return None
    for item in payload.get("acceptance_fixtures") or []:
        if isinstance(item, Mapping) and str(item.get("id") or "") == fixture_id:
            return dict(item)
    return None


def _graphics_combined_contract_errors(run_dir: Path) -> list[str]:
    """Validate the cross-artifact identity chain for the P7 graphics fixture.

    Hashes prove that retained files were not changed after capture, while this
    contract proves that Present, matrix, projection, and overlay evidence all
    describe the same process/window/frame.  Missing files remain the generic
    registered-artifact check's responsibility.
    """
    names = {
        "target": "graphics-combined/target-identity.json",
        "present": "graphics-combined/present-observation.json",
        "matrix": "graphics-combined/matrix-capture.json",
        "projection": "graphics-combined/projection.json",
        "overlay": "graphics-combined/overlay-audit.json",
        "cleanup": "graphics-combined/cleanup.json",
        "proof": "graphics-combined/execution-proof.json",
    }
    payloads: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for key, relative in names.items():
        path = run_dir / relative
        if not path.is_file():
            errors.append(f"VLM contract artifact is missing: {relative}")
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append(f"VLM contract artifact is invalid JSON: {relative}")
            continue
        if not isinstance(value, Mapping):
            errors.append(f"VLM contract artifact must be a JSON object: {relative}")
            continue
        payloads[key] = dict(value)

    if errors:
        return errors
    target = payloads["target"]
    pid = target.get("pid")
    hwnd = (target.get("metadata") or {}).get("hwnd") if isinstance(target.get("metadata"), Mapping) else target.get("hwnd")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        errors.append("graphics target identity must contain a positive pid")
    if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
        errors.append("graphics target identity must contain a positive hwnd")

    present = payloads["present"]
    if str(present.get("status") or "").lower() not in _SUCCESS_VALUES:
        errors.append("graphics present observation is not successful")
    if pid and present.get("target_pid") != pid:
        errors.append("graphics present target_pid does not match target identity")
    last_event = present.get("last_event")
    if isinstance(last_event, Mapping) and pid and last_event.get("pid") not in (None, pid):
        errors.append("graphics present last_event pid does not match target identity")

    matrix = payloads["matrix"]
    frame_id = str(matrix.get("frame_id") or "").strip()
    if str(matrix.get("status") or "").lower() not in _SUCCESS_VALUES:
        errors.append("graphics matrix capture is not successful")
    if matrix.get("source") != "native_host_bridge":
        errors.append("graphics matrix capture must come from native_host_bridge")
    if pid and matrix.get("pid") != pid:
        errors.append("graphics matrix pid does not match target identity")
    if hwnd and matrix.get("hwnd") != hwnd:
        errors.append("graphics matrix hwnd does not match target identity")
    if not frame_id:
        errors.append("graphics matrix capture is missing frame_id")
    values = matrix.get("matrix")
    if not isinstance(values, list) or len(values) != 16:
        errors.append("graphics matrix capture must contain 16 matrix values")
    if present.get("matrix_frame_id") != frame_id:
        errors.append("graphics present and matrix frame IDs do not match")

    projection = payloads["projection"]
    if str(projection.get("status") or "").lower() not in _SUCCESS_VALUES:
        errors.append("graphics projection is not successful")
    if projection.get("matrix_frame_id") not in (None, frame_id):
        errors.append("graphics projection frame ID does not match matrix capture")
    if not isinstance(projection.get("visible_point_count"), int) or projection.get("visible_point_count", 0) <= 0:
        errors.append("graphics projection has no visible point")

    overlay = payloads["overlay"]
    if str(overlay.get("status") or "").lower() not in _SUCCESS_VALUES:
        errors.append("graphics overlay audit is not successful")
    overlay_provenance = overlay.get("provenance")
    if isinstance(overlay_provenance, Mapping) and overlay_provenance.get("matrix_frame_id") not in (None, frame_id):
        errors.append("graphics overlay frame ID does not match matrix capture")

    cleanup = payloads["cleanup"]
    for key in ("verified", "rollback_verified", "cleanup_verified"):
        if cleanup.get(key) is not True:
            errors.append(f"graphics cleanup proof {key} is not true")
    proof = payloads["proof"]
    if str(proof.get("status") or "").lower() not in _SUCCESS_VALUES:
        errors.append("graphics execution proof is not successful")
    if proof.get("skipped_tests") != 0 or proof.get("executed_tests", 0) < 1:
        errors.append("graphics execution proof must have one executed and zero skipped tests")
    return errors


def _imgui_contract_errors(run_dir: Path) -> list[str]:
    """Bind the retained ImGui plugin and native host lifecycle evidence."""

    names = {
        "target": "imgui/target-identity.json",
        "plugin": "imgui/renderer-plugin.json",
        "frame": "imgui/frame-lifecycle.json",
        "restoration": "imgui/hook-restoration.json",
        "proof": "imgui/execution-proof.json",
    }
    payloads: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for key, relative in names.items():
        path = run_dir / relative
        if not path.is_file():
            errors.append(f"ImGui contract artifact is missing: {relative}")
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append(f"ImGui contract artifact is invalid JSON: {relative}")
            continue
        if not isinstance(value, Mapping):
            errors.append(f"ImGui contract artifact must be a JSON object: {relative}")
            continue
        payloads[key] = dict(value)
    plugin_binary = run_dir / "imgui/reverse_analyzer_imgui_renderer.dll"
    if not plugin_binary.is_file():
        errors.append("ImGui retained plugin binary is missing")
    if errors:
        return errors

    target = payloads["target"]
    target_hash = _json_hash(target)
    target_pid = target.get("pid")
    if type(target_pid) is not int or target_pid <= 0 or target.get("kind") != "process":
        errors.append("ImGui target identity must be a process with a positive PID")

    plugin = payloads["plugin"]
    plugin_hash = str(plugin.get("sha256") or "").lower()
    if not (len(plugin_hash) == 64 and all(char in "0123456789abcdef" for char in plugin_hash)):
        errors.append("ImGui renderer plugin sha256 is invalid")
    else:
        if _sha256(plugin_binary) != plugin_hash:
            errors.append("ImGui retained plugin binary sha256 does not match renderer manifest")
    if plugin.get("size") != plugin_binary.stat().st_size:
        errors.append("ImGui retained plugin binary size does not match renderer manifest")
    if (
        str(plugin.get("status") or "").lower() not in _SUCCESS_VALUES
        or plugin.get("production_build") is not True
        or plugin.get("official_imgui_origin_verified") is not True
        or plugin.get("retained_binary") != "imgui/reverse_analyzer_imgui_renderer.dll"
    ):
        errors.append("ImGui renderer plugin is not a retained official production build")

    operations = ("load", "initialize", "install_hook", "frame_evidence", "shutdown", "unload")
    frame = payloads["frame"]
    plan = frame.get("plan") if isinstance(frame.get("plan"), Mapping) else {}
    execution = frame.get("execution") if isinstance(frame.get("execution"), Mapping) else {}
    artifacts = frame.get("artifacts") if isinstance(frame.get("artifacts"), Mapping) else {}
    provenance = artifacts.get("provenance") if isinstance(artifacts.get("provenance"), Mapping) else {}
    lifecycle = execution.get("lifecycle") if isinstance(execution.get("lifecycle"), list) else []
    session_id = str(frame.get("session_id") or "")
    precondition_hash = str(plan.get("precondition_hash") or "")
    if (
        frame.get("status") != "ok"
        or frame.get("fixture_id") != "p4-imgui-d3d11-live"
        or not session_id
        or plan.get("target_identity") != target
        or plan.get("target_identity_hash") != target_hash
        or plan.get("backend") != "d3d11"
        or tuple(plan.get("operations") or ()) != operations
    ):
        errors.append("ImGui frame plan does not bind the registered target and D3D11 lifecycle")
    if (
        execution.get("status") != "ok"
        or execution.get("live_verified") is not True
        or execution.get("evidence_class") != "live_host_proof"
        or len(lifecycle) != len(operations)
    ):
        errors.append("ImGui frame execution is not a complete live host lifecycle")

    for sequence, operation in enumerate(operations, start=1):
        item = lifecycle[sequence - 1] if len(lifecycle) >= sequence and isinstance(lifecycle[sequence - 1], Mapping) else {}
        proof = item.get("proof") if isinstance(item.get("proof"), Mapping) else {}
        cleanup = (
            item.get("bridge_call", {}).get("process_cleanup", {})
            if isinstance(item.get("bridge_call"), Mapping)
            and isinstance(item.get("bridge_call", {}).get("process_cleanup"), Mapping)
            else {}
        )
        if (
            item.get("operation") != operation
            or item.get("sequence") != sequence
            or item.get("session_id") != session_id
            or item.get("target_identity_hash") != target_hash
            or item.get("precondition_hash") != precondition_hash
            or item.get("backend") != "d3d11"
            or item.get("evidence_class") != "live_host_proof"
            or item.get("live_verified") is not True
            or proof.get("source") != "native_host_bridge"
            or proof.get("observed") is not True
            or not str(proof.get("observed_at") or "")
            or cleanup.get("process_exited") is not True
        ):
            errors.append(f"ImGui lifecycle operation is not bound or verified: {operation}")

    if (
        provenance.get("session_id") != session_id
        or provenance.get("target_identity_hash") != target_hash
        or provenance.get("precondition_hash") != precondition_hash
        or provenance.get("backend") != "d3d11"
        or provenance.get("evidence_class") != "live_host_proof"
        or provenance.get("live_verified") is not True
    ):
        errors.append("ImGui lifecycle provenance does not match the host plan")
    bridge_identity = frame.get("bridge_identity") if isinstance(frame.get("bridge_identity"), Mapping) else {}
    bridge_hash = str(bridge_identity.get("executable_sha256") or "").lower()
    if (
        bridge_identity.get("adapter") != "local_json_subprocess"
        or bridge_identity.get("protocol") != "reverse-analyzer.native-bridge"
        or bridge_identity.get("protocol_version") != 1
        or bridge_identity.get("capability") != "imgui_renderer_runtime"
        or len(bridge_hash) != 64
        or any(char not in "0123456789abcdef" for char in bridge_hash)
    ):
        errors.append("ImGui frame lifecycle lacks a stable production bridge identity")

    restoration = payloads["restoration"]
    if any(restoration.get(key) is not True for key in (
        "verified", "rollback_verified", "cleanup_verified", "renderer_shutdown", "module_unloaded", "hook_restored"
    )):
        errors.append("ImGui hook restoration is incomplete")
    if restoration.get("shutdown") != (lifecycle[4] if len(lifecycle) > 4 else None) or restoration.get("unload") != (lifecycle[5] if len(lifecycle) > 5 else None):
        errors.append("ImGui hook restoration does not bind the shutdown/unload lifecycle")

    proof = payloads["proof"]
    if (
        str(proof.get("status") or "").lower() not in _SUCCESS_VALUES
        or proof.get("provider") != plugin.get("provider")
        or proof.get("evidence_class") != "live_host_proof"
        or proof.get("executed_tests") != 1
        or proof.get("skipped_tests") != 0
        or proof.get("live_operations") != len(operations)
        or tuple(proof.get("actions") or ()) != operations
        or proof.get("plugin_sha256") != plugin_hash
    ):
        errors.append("ImGui execution proof does not bind the plugin and complete lifecycle")
    return errors


def _vlm_contract_errors(run_dir: Path) -> list[str]:
    """Validate semantic bindings for the retained P7 VLM live record.

    Artifact hashes prove retention, but the VLM record also needs to prove
    that the HTTP response, input image and canary all belong to one request.
    Secrets and endpoint URL material are intentionally absent from this
    contract; only their content-addressed identity may be retained.
    """
    names = {
        "target": "gui-vlm/target-identity.json",
        "invocation": "gui-vlm/invocation.json",
        "output": "gui-vlm/output.json",
        "transport": "gui-vlm/transport-audit.json",
        "canary": "gui-vlm/canary-verification.json",
        "proof": "gui-vlm/execution-proof.json",
    }
    payloads: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    present = False
    for key, relative in names.items():
        path = run_dir / relative
        if not path.is_file():
            continue
        present = True
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append(f"VLM artifact invalid JSON: {relative}")
            continue
        if not isinstance(value, Mapping):
            errors.append(f"VLM artifact must be a JSON object: {relative}")
            continue
        payloads[key] = dict(value)

    # Records without any VLM artifacts are handled by the generic artifact
    # contract. Once a VLM artifact appears, report every missing or malformed
    # member explicitly so retained records cannot fail silently.
    if not present:
        return []
    for key, relative in names.items():
        if key not in payloads and not any(relative in error for error in errors):
            errors.append(f"VLM artifact is missing: {relative}")
    if len(payloads) != len(names):
        return errors

    target = payloads["target"]

    def digest(value: Any, label: str) -> str:
        text = str(value or "").strip().lower()
        if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
            errors.append(f"VLM {label} must be a SHA-256 digest")
            return ""
        return text

    image_digest = digest(target.get("image_sha256"), "image_sha256")
    identity_digest = digest(target.get("sha256"), "target sha256")
    canary_digest = digest(target.get("canary_sha256"), "canary_sha256")
    digest(target.get("endpoint_sha256"), "endpoint_sha256")
    if image_digest and identity_digest and image_digest != identity_digest:
        errors.append("VLM target sha256 does not match image_sha256")
    target_model = str(target.get("model") or "").strip()
    if not target_model:
        errors.append("VLM target identity is missing model")

    invocation = payloads["invocation"]
    if str(invocation.get("status") or "").lower() not in _SUCCESS_VALUES:
        errors.append("VLM invocation is not successful")
    output = payloads["output"]
    if str(output.get("status") or "").lower() not in _SUCCESS_VALUES:
        errors.append("VLM output is not successful")
    visual_items = sum(
        len(output.get(key))
        for key in ("text_regions", "widgets")
        if isinstance(output.get(key), list)
    )
    if visual_items < 1:
        errors.append("VLM output contains no visual evidence")
    provenance = output.get("provenance")
    if not isinstance(provenance, Mapping) or not str(provenance.get("provider") or "").strip():
        errors.append("VLM output is missing provider provenance")
    elif target_model and str(provenance.get("model") or "").strip() != target_model:
        errors.append("VLM output model does not match target identity")

    transport = payloads["transport"]
    if str(transport.get("status") or "").lower() not in _SUCCESS_VALUES:
        errors.append("VLM transport audit is not successful")
    if transport.get("transport") != "openai-compatible-http":
        errors.append("VLM transport audit must identify openai-compatible-http")
    if transport.get("authorization_persisted") is not False:
        errors.append("VLM transport audit must confirm authorization was not persisted")
    if transport.get("secret_source") != "environment":
        errors.append("VLM transport secret source must be environment-backed")
    if transport.get("canary_verified") is not True:
        errors.append("VLM transport audit must confirm canary verification")
    input_digest = str(transport.get("input_sha256") or "").strip().lower()
    if image_digest and input_digest != image_digest:
        errors.append("VLM transport input digest does not match target image digest")

    canary = payloads["canary"]
    if canary.get("verified") is not True:
        errors.append("VLM canary verification is not true")
    if canary_digest and str(canary.get("canary_sha256") or "").strip().lower() != canary_digest:
        errors.append("VLM canary digest does not match target identity")
    if not isinstance(canary.get("matched_items"), int) or canary.get("matched_items", 0) < 1:
        errors.append("VLM canary verification has no matched item")

    proof = payloads["proof"]
    if str(proof.get("status") or "").lower() not in _SUCCESS_VALUES:
        errors.append("VLM execution proof is not successful")
    if proof.get("skipped_tests") != 0 or proof.get("executed_tests", 0) < 1:
        errors.append("VLM execution proof must have one executed and zero skipped tests")
    if proof.get("canary_verified") is not True:
        errors.append("VLM execution proof must confirm canary verification")
    return errors


def _matching_files(run_dir: Path, patterns: Sequence[Any]) -> tuple[list[Path], list[str]]:
    observed: list[Path] = []
    missing: list[str] = []
    for raw in patterns:
        pattern = _safe_relative_pattern(raw)
        matches = sorted(path.resolve() for path in run_dir.glob(pattern) if path.is_file())
        matches = [path for path in matches if _inside(path, run_dir)]
        if not matches:
            missing.append(pattern)
        for path in matches:
            if path not in observed:
                observed.append(path)
    return observed, missing


def _artifact_entries(paths: Sequence[Path], run_dir: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(set(paths)):
        entries.append(
            {
                "path": path.relative_to(run_dir).as_posix(),
                "size": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    return entries


def list_acceptance_fixtures(
    *,
    environ: Mapping[str, str] | None = None,
    system: str | None = None,
) -> list[dict[str, Any]]:
    """Return fixture readiness using the same environment contract as doctor."""

    report = validate_external_environment(
        execute_probes=False,
        environ=environ,
        system=system,
    )
    return [dict(item) for item in report.get("acceptance_fixtures") or []]


def run_acceptance_fixture(
    fixture_id: str,
    workspace: str | Path,
    *,
    execute: bool,
    timeout: float = 300.0,
    target_identity: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] | None = None,
    system: str | None = None,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Execute one registered fixture and persist an immutable acceptance record."""

    fixtures = _fixture_map()
    if fixture_id not in fixtures:
        raise AcceptanceError(f"unknown acceptance fixture: {fixture_id}")
    if not execute:
        raise AcceptanceError("acceptance execution requires explicit execute=True")

    fixture = fixtures[fixture_id]
    root = _safe_workspace(workspace)
    session_id = uuid.uuid4().hex
    run_dir = (root / "acceptance" / "runs" / fixture_id / session_id).resolve()
    records_dir = (root / "acceptance" / "records").resolve()
    if not _inside(run_dir, root) or not _inside(records_dir, root):
        raise AcceptanceError("acceptance output escaped the workspace")
    run_dir.mkdir(parents=True, exist_ok=False)
    records_dir.mkdir(parents=True, exist_ok=True)

    environment = dict(os.environ if environ is None else environ)
    run_env = fixture.get("run_env") or {}
    if not isinstance(run_env, Mapping):
        raise AcceptanceError(f"fixture {fixture_id} has an invalid run_env contract")
    environment.update({str(key): str(value) for key, value in run_env.items()})
    environment["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"] = str(run_dir)
    environment["REVERSE_ANALYZER_ACCEPTANCE_SESSION_ID"] = session_id

    environment_report = validate_external_environment(
        execute_probes=True,
        timeout=min(max(float(timeout), 0.1), 15.0),
        environ=environment,
        system=system,
    )
    write_environment_report(environment_report, run_dir / "environment-validation.json")
    readiness = {
        str(item.get("id")): item
        for item in environment_report.get("acceptance_fixtures") or []
        if isinstance(item, Mapping)
    }.get(fixture_id, {})
    readiness_status = str(readiness.get("status") or "dependency_gated")

    argv = _registered_argv(fixture)
    started_at = _utc_now()
    stdout = ""
    stderr = ""
    exit_code: int | None = None
    execution_error: str | None = None
    if readiness_status in {"unsupported_host", "dependency_gated"}:
        outcome = readiness_status
    else:
        try:
            completed = runner(
                argv,
                cwd=str(Path(__file__).resolve().parents[1]),
                env=environment,
                capture_output=True,
                text=True,
                timeout=max(float(timeout), 0.1),
                check=False,
            )
            exit_code = int(completed.returncode)
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            outcome = "passed" if exit_code == 0 else "failed"
        except (OSError, subprocess.SubprocessError) as exc:
            outcome = "failed"
            execution_error = f"{type(exc).__name__}: {exc}"

    stdout_path = run_dir / "stdout.log"
    stderr_path = run_dir / "stderr.log"
    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(stderr, encoding="utf-8", errors="replace")

    expected_patterns = list(fixture.get("expected_artifacts") or [])
    expected_files, missing_artifacts = _matching_files(run_dir, expected_patterns)
    observed_identity, missing_identity_artifact = _load_target_identity(run_dir, fixture)
    if missing_identity_artifact and missing_identity_artifact not in missing_artifacts:
        missing_artifacts.append(missing_identity_artifact)
    requested_identity = dict(target_identity or {})
    effective_identity = observed_identity or requested_identity
    identity_matches = _target_identities_match(requested_identity, observed_identity)
    rollback_files, _ = _matching_files(run_dir, fixture.get("rollback_artifacts") or [])
    cleanup_files, _ = _matching_files(run_dir, fixture.get("cleanup_artifacts") or [])
    mutating = bool(fixture.get("mutating"))
    rollback_result = _fixture_proof_ok(
        rollback_files,
        required=mutating,
        fixture_id=fixture_id,
        role="rollback",
    )
    cleanup_required = mutating or bool(fixture.get("cleanup_artifacts"))
    cleanup_result = _fixture_proof_ok(
        cleanup_files,
        required=cleanup_required,
        fixture_id=fixture_id,
        role="cleanup",
    )
    provenance_valid, rejected_provenance = _artifact_provenance_valid(expected_files)
    fixture_contract_errors = (
        _graphics_combined_contract_errors(run_dir)
        if fixture_id == "p7-graphics-combined-live"
        else _imgui_contract_errors(run_dir)
        if fixture_id == "p4-imgui-d3d11-live"
        else _vlm_contract_errors(run_dir)
        if fixture_id == "p7-vlm-openai-live"
        else []
    )
    target_valid = _fixture_target_identity_valid(
        effective_identity,
        fixture_id=fixture_id,
    ) and identity_matches
    live_capable = str(fixture.get("evidence_level")) in _LIVE_EVIDENCE_LEVELS
    execution_proof: dict[str, Any] = {}
    execution_proof_errors: list[str] = []
    execution_proof_valid = True
    execution_proof_path: Path | None = None
    if live_capable:
        execution_proof, missing_execution_proof, execution_proof_path = _load_json_artifact(
            run_dir,
            fixture.get("execution_proof_artifact"),
        )
        if missing_execution_proof and missing_execution_proof not in missing_artifacts:
            missing_artifacts.append(missing_execution_proof)
        execution_proof_valid, execution_proof_errors = _execution_proof_valid(
            execution_proof,
            required_executed_tests=max(
                1,
                int(fixture.get("required_executed_tests") or 1),
            ),
        )
        # The proof is retained evidence too; apply the same provenance
        # policy as the fixture's expected artifacts.
        provenance_paths = [*expected_files]
        if execution_proof_path is not None and execution_proof_path not in provenance_paths:
            provenance_paths.append(execution_proof_path)
        provenance_valid, rejected_provenance = _artifact_provenance_valid(provenance_paths)
    constraints = {
        "registered_fixture": True,
        "structured_argv": True,
        "host_and_dependencies_ready": readiness_status in {"ready_to_run", "repository_ready"},
        "execution_passed": outcome == "passed" and exit_code == 0,
        "live_evidence_level": live_capable,
        "execution_proof_valid": execution_proof_valid,
        "target_identity_present": target_valid,
        "target_identity_matches_artifact": identity_matches,
        "expected_artifacts_complete": not missing_artifacts,
        "provenance_non_synthetic": provenance_valid,
        "rollback_verified": bool(rollback_result["verified"]),
        "cleanup_verified": bool(cleanup_result["verified"]),
        "fixture_contract_valid": not fixture_contract_errors,
    }
    live_verified = all(constraints.values())
    retained = [stdout_path, stderr_path, run_dir / "environment-validation.json", *expected_files]
    if execution_proof_path is not None and execution_proof_path not in retained:
        retained.append(execution_proof_path)
    finished_at = _utc_now()
    record_path = records_dir / f"{fixture_id}--{session_id}.json"
    record = {
        "schema_version": 1,
        "fixture_id": fixture_id,
        "phase": fixture.get("phase"),
        "capability": fixture.get("capability"),
        "evidence_level": fixture.get("evidence_level"),
        "session_id": session_id,
        "target_identity": effective_identity,
        "target_identity_source": (
            "artifact" if observed_identity else "request" if requested_identity else "missing"
        ),
        "started_at": started_at,
        "finished_at": finished_at,
        "workspace": str(root),
        "run_directory": str(run_dir),
        "record_path": str(record_path),
        "command": argv,
        "command_display": fixture.get("command"),
        "contract_sha256": _json_hash(fixture),
        "environment_gates": {
            "status": readiness_status,
            "configured": list(readiness.get("configured_gates") or []),
            "missing": list(readiness.get("missing_gates") or []),
            "workflow_states": dict(readiness.get("workflow_states") or {}),
        },
        "provider_versions": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "expected_artifacts": [_safe_relative_pattern(item) for item in expected_patterns],
        "observed_artifacts": _artifact_entries(retained, run_dir),
        "missing_artifacts": missing_artifacts,
        "rejected_provenance": rejected_provenance,
        "execution_proof": execution_proof,
        "execution_proof_errors": execution_proof_errors,
        "fixture_contract_errors": fixture_contract_errors,
        "execution_proof_artifact": fixture.get("execution_proof_artifact"),
        "rollback_result": rollback_result,
        "cleanup_result": cleanup_result,
        "exit_code": exit_code,
        "execution_error": execution_error,
        "outcome": outcome,
        "verification_constraints": constraints,
        "live_verified": live_verified,
    }
    record_path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return record


def verify_acceptance_record(record_file: str | Path) -> dict[str, Any]:
    """Recompute retained artifact hashes and validate any live-proof claim."""

    path = Path(record_file).expanduser().resolve()
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"status": "failed", "record": str(path), "errors": [f"{type(exc).__name__}: {exc}"]}
    if not isinstance(record, Mapping):
        return {"status": "failed", "record": str(path), "errors": ["record must be a JSON object"]}
    run_dir = Path(str(record.get("run_directory") or "")).expanduser().resolve()
    workspace = Path(str(record.get("workspace") or "")).expanduser().resolve()
    errors: list[str] = []
    if not _inside(path, workspace) or not _inside(run_dir, workspace):
        errors.append("record or run directory is outside the recorded workspace")
    fixture_id = str(record.get("fixture_id") or "")
    fixture = _fixture_map().get(fixture_id)
    if fixture is None:
        errors.append(f"record references an unknown fixture: {fixture_id or '<missing>'}")
    elif record.get("contract_sha256") != _json_hash(fixture):
        errors.append("registered fixture contract hash mismatch")
    entries = record.get("observed_artifacts")
    if not isinstance(entries, list):
        errors.append("observed_artifacts must be a list")
        entries = []
    verified = 0
    for entry in entries:
        if not isinstance(entry, Mapping):
            errors.append("invalid artifact entry")
            continue
        try:
            relative = _safe_relative_pattern(entry.get("path"))
        except AcceptanceError as exc:
            errors.append(str(exc))
            continue
        artifact = (run_dir / relative).resolve()
        if not _inside(artifact, run_dir) or not artifact.is_file():
            errors.append(f"missing artifact: {relative}")
            continue
        if artifact.stat().st_size != entry.get("size"):
            errors.append(f"size mismatch: {relative}")
            continue
        if _sha256(artifact) != entry.get("sha256"):
            errors.append(f"sha256 mismatch: {relative}")
            continue
        verified += 1
    if record.get("live_verified") is True:
        # Recompute the registered contract from retained files.  Hash checks
        # alone protect bytes, but do not prove that the bytes satisfy the
        # fixture's target, rollback, cleanup, and provenance requirements.
        if fixture is not None:
            try:
                registered_argv = _registered_argv(fixture)
            except AcceptanceError as exc:
                errors.append(str(exc))
            else:
                command = record.get("command")
                if command != registered_argv:
                    errors.append("record command does not match registered fixture argv")
            expected = [_safe_relative_pattern(item) for item in fixture.get("expected_artifacts") or []]
            if record.get("expected_artifacts") != expected:
                errors.append("record expected_artifacts do not match registered fixture")
            observed_files, missing = _matching_files(run_dir, fixture.get("expected_artifacts") or [])
            if missing:
                errors.extend(f"missing expected artifact: {item}" for item in missing)
            identity, missing_identity = _load_target_identity(run_dir, fixture)
            if missing_identity:
                errors.append(f"missing target identity artifact: {missing_identity}")
            if not _target_identity_valid(identity):
                errors.append("target identity artifact is missing a stable identity field")
            recorded_identity = record.get("target_identity")
            if not isinstance(recorded_identity, Mapping):
                errors.append("record target_identity must be an object")
            elif not _target_identities_match(recorded_identity, identity):
                errors.append("record target identity does not match retained target identity artifact")
            provenance_valid, rejected = _artifact_provenance_valid(observed_files)
            proof_path = _load_json_artifact(run_dir, fixture.get("execution_proof_artifact"))[2]
            if proof_path is not None and proof_path not in observed_files:
                proof_provenance_valid, proof_rejected = _artifact_provenance_valid([proof_path])
                provenance_valid = provenance_valid and proof_provenance_valid
                rejected = [*rejected, *proof_rejected]
            if not provenance_valid:
                errors.extend(f"synthetic provenance in artifact: {item}" for item in rejected)
            rollback_files, _ = _matching_files(run_dir, fixture.get("rollback_artifacts") or [])
            cleanup_files, _ = _matching_files(run_dir, fixture.get("cleanup_artifacts") or [])
            if not _fixture_proof_ok(
                rollback_files,
                required=bool(fixture.get("mutating")),
                fixture_id=fixture_id,
                role="rollback",
            )["verified"]:
                errors.append("rollback proof is missing or unverified")
            if not _fixture_proof_ok(
                cleanup_files,
                required=bool(fixture.get("mutating") or fixture.get("cleanup_artifacts")),
                fixture_id=fixture_id,
                role="cleanup",
            )["verified"]:
                errors.append("cleanup proof is missing or unverified")
            if record.get("outcome") != "passed" or record.get("exit_code") != 0:
                errors.append("live_verified record does not have a successful command outcome")
            if fixture_id == "p7-graphics-combined-live":
                errors.extend(_graphics_combined_contract_errors(run_dir))
            if fixture_id == "p4-imgui-d3d11-live":
                errors.extend(_imgui_contract_errors(run_dir))
            if fixture_id == "p7-vlm-openai-live":
                errors.extend(_vlm_contract_errors(run_dir))
        constraints = record.get("verification_constraints")
        if not isinstance(constraints, Mapping) or not constraints or not all(value is True for value in constraints.values()):
            errors.append("live_verified claim lacks complete verification constraints")
        if fixture is not None:
            proof, missing_proof, _ = _load_json_artifact(
                run_dir,
                fixture.get("execution_proof_artifact"),
            )
            proof_valid, proof_errors = _execution_proof_valid(
                proof,
                required_executed_tests=max(
                    1,
                    int(fixture.get("required_executed_tests") or 1),
                ),
            )
            if missing_proof or not proof_valid:
                errors.extend(proof_errors or [f"missing execution proof: {missing_proof}"])
            # Recompute every persisted constraint from the registered fixture
            # and retained evidence. Hashes and a user-editable boolean map
            # alone must not be sufficient to promote a live record.
            observed_identity, missing_identity = _load_target_identity(run_dir, fixture)
            recorded_identity = record.get("target_identity")
            try:
                registered_command = _registered_argv(fixture)
            except AcceptanceError:
                registered_command = []
            expected_files, missing_expected = _matching_files(
                run_dir, fixture.get("expected_artifacts") or []
            )
            proof_path = _load_json_artifact(run_dir, fixture.get("execution_proof_artifact"))[2]
            provenance_files = [*expected_files]
            if proof_path is not None and proof_path not in provenance_files:
                provenance_files.append(proof_path)
            rollback_files, _ = _matching_files(run_dir, fixture.get("rollback_artifacts") or [])
            cleanup_files, _ = _matching_files(run_dir, fixture.get("cleanup_artifacts") or [])
            environment_state = _environment_fixture_state(run_dir, fixture_id)
            recorded_environment = record.get("environment_gates")
            environment_status = (
                str(environment_state.get("status") or "")
                if environment_state is not None
                else ""
            )
            recomputed_constraints = {
                "registered_fixture": True,
                "structured_argv": record.get("command") == registered_command,
                "host_and_dependencies_ready": environment_status in {"ready_to_run", "repository_ready"}
                and isinstance(recorded_environment, Mapping)
                and recorded_environment.get("status") == environment_status
                and recorded_environment.get("configured") == list(
                    environment_state.get("configured_gates") or []
                )
                and recorded_environment.get("missing") == list(
                    environment_state.get("missing_gates") or []
                ),
                "execution_passed": record.get("outcome") == "passed" and record.get("exit_code") == 0,
                "live_evidence_level": str(fixture.get("evidence_level")) in _LIVE_EVIDENCE_LEVELS,
                "execution_proof_valid": proof_valid,
                "target_identity_present": _fixture_target_identity_valid(
                    observed_identity,
                    fixture_id=fixture_id,
                ),
                "target_identity_matches_artifact": (
                    not bool(missing_identity)
                    and _target_identities_match(
                        recorded_identity if isinstance(recorded_identity, Mapping) else None,
                        observed_identity,
                    )
                ),
                "expected_artifacts_complete": not missing_expected,
                "provenance_non_synthetic": _artifact_provenance_valid(provenance_files)[0],
                "rollback_verified": _fixture_proof_ok(
                    rollback_files,
                    required=bool(fixture.get("mutating")),
                    fixture_id=fixture_id,
                    role="rollback",
                )["verified"],
                "cleanup_verified": _fixture_proof_ok(
                    cleanup_files,
                    required=bool(fixture.get("mutating") or fixture.get("cleanup_artifacts")),
                    fixture_id=fixture_id,
                    role="cleanup",
                )["verified"],
                "fixture_contract_valid": not bool(
                    (
                        _graphics_combined_contract_errors(run_dir)
                        if fixture_id == "p7-graphics-combined-live"
                        else _imgui_contract_errors(run_dir)
                        if fixture_id == "p4-imgui-d3d11-live"
                        else _vlm_contract_errors(run_dir)
                        if fixture_id == "p7-vlm-openai-live"
                        else []
                    )
                ),
            }
            if dict(constraints or {}) != recomputed_constraints:
                errors.append("verification_constraints do not match recomputed acceptance state")
    return {
        "status": "ok" if not errors else "failed",
        "record": str(path),
        "fixture_id": record.get("fixture_id"),
        "live_verified": bool(record.get("live_verified")) and not errors,
        "verified_artifacts": verified,
        "errors": errors,
    }


def load_acceptance_records(workspace: str | Path) -> list[dict[str, Any]]:
    """Load valid JSON records without trusting their live-proof integrity."""

    root = Path(workspace).expanduser().resolve()
    records_dir = root / "acceptance" / "records"
    records: list[dict[str, Any]] = []
    if not records_dir.is_dir():
        return records
    for path in sorted(records_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, Mapping):
            continue
        item = dict(payload)
        integrity = verify_acceptance_record(path)
        item["declared_live_verified"] = item.get("live_verified") is True
        item["integrity"] = integrity
        item["live_verified"] = integrity.get("live_verified") is True
        records.append(item)
    return records


def merge_acceptance_records(
    report: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Attach record history and verified latest state to an environment report."""

    merged = dict(report)
    history: list[dict[str, Any]] = []
    for raw in records:
        item = dict(raw)
        integrity = item.get("integrity")
        item["declared_live_verified"] = (
            item.get("declared_live_verified") is True
            or item.get("live_verified") is True
        )
        item["live_verified"] = (
            isinstance(integrity, Mapping)
            and integrity.get("status") == "ok"
            and integrity.get("live_verified") is True
        )
        history.append(item)
    latest: dict[str, dict[str, Any]] = {}
    for item in history:
        fixture_id = str(item.get("fixture_id") or "")
        if not fixture_id:
            continue
        current = latest.get(fixture_id)
        if current is None or str(item.get("finished_at") or "") >= str(current.get("finished_at") or ""):
            latest[fixture_id] = item
    fixtures: list[dict[str, Any]] = []
    for raw in report.get("acceptance_fixtures") or []:
        if not isinstance(raw, Mapping):
            continue
        fixture = dict(raw)
        record = latest.get(str(fixture.get("id") or ""))
        if record is not None:
            integrity = record.get("integrity")
            valid_live = (
                record.get("live_verified") is True
                and isinstance(integrity, Mapping)
                and integrity.get("status") == "ok"
                and integrity.get("live_verified") is True
            )
            fixture["latest_acceptance_record"] = record.get("record_path")
            fixture["latest_acceptance_outcome"] = record.get("outcome")
            fixture["live_verified"] = valid_live
            if valid_live:
                fixture["status"] = "live_verified"
        fixtures.append(fixture)
    merged["acceptance_fixtures"] = fixtures
    merged["acceptance_records"] = history
    summary = dict(merged.get("summary") or {})
    summary["acceptance_record_total"] = len(history)
    summary["acceptance_fixture_live_verified"] = sum(item.get("live_verified") is True for item in fixtures)
    summary["acceptance_record_failed"] = sum(str(item.get("outcome")) == "failed" for item in history)
    merged["summary"] = summary
    return merged


__all__ = [
    "AcceptanceError",
    "list_acceptance_fixtures",
    "load_acceptance_records",
    "merge_acceptance_records",
    "run_acceptance_fixture",
    "verify_acceptance_record",
]
