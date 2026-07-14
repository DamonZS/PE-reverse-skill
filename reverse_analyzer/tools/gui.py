"""Dependency-light GUI reverse-engineering helpers."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import zipfile
from typing import Any, Dict, Iterable, Mapping

from ..gui.world_projection import WorldProjectionEngine, write_projection_artifact
from ..gui.vlm_provider import load_vlm_provider
from ..gui.windows_uia import WINDOWS_UIA_BACKEND, probe_windows_uia
from .executor import ToolResult
from .gui_runtime_adapters import (
    RuntimeProviderError,
    probe_android_uiautomator,
    probe_ios_accessibility,
)

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".ico", ".webp"}
SCREENSHOT_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}
MAX_RESOURCE_FILES = 500
MAX_RESOURCE_FILE_BYTES = 16 * 1024 * 1024

STRATEGY_MAP: Dict[str, Dict[str, Any]] = {
    "electron": {
        "name": "extract_asar_rebuild_electron",
        "output_stack": "electron",
        "steps": ["resource_extract", "asar_extract", "generate_electron_project", "visual_regression"],
        "reason": "Electron packages usually preserve original HTML/CSS/JS assets.",
    },
    "wpf": {
        "name": "extract_baml_generate_wpf",
        "output_stack": "wpf",
        "steps": ["resource_extract", "baml_decompile", "event_handler_trace", "generate_wpf_project", "visual_regression"],
        "reason": "WPF resources often preserve BAML/XAML layout metadata.",
    },
    "winforms": {
        "name": "decompile_initialize_component_generate_winforms",
        "output_stack": "winforms",
        "steps": ["decompiler", "resx_extract", "event_handler_trace", "generate_winforms_project", "visual_regression"],
        "reason": "WinForms layout and event wiring are usually recoverable from IL and resources.",
    },
    "qt": {
        "name": "extract_qrc_probe_qwidget_generate_qt",
        "output_stack": "qt_or_pyside6",
        "steps": ["resource_extract", "qrc_extract", "runtime_probe", "generate_qt_project", "visual_regression"],
        "reason": "Qt applications may expose .ui/.qrc assets and QWidget runtime structure.",
    },
    "win32_dialog": {
        "name": "extract_dialog_resources_generate_win32",
        "output_stack": "win32_cpp",
        "steps": ["resource_extract", "dialog_template_parse", "wndproc_trace", "generate_win32_project", "visual_regression"],
        "reason": "Win32 dialog resources can be converted directly into native UI code.",
    },
    "mfc": {
        "name": "extract_resources_trace_message_maps_generate_mfc",
        "output_stack": "mfc_or_win32_cpp",
        "steps": ["resource_extract", "message_map_trace", "generate_cpp_project", "visual_regression"],
        "reason": "MFC apps combine Win32 resources with message maps and runtime classes.",
    },
    "delphi_vcl": {
        "name": "extract_dfm_generate_delphi_or_lazarus",
        "output_stack": "delphi_lazarus",
        "steps": ["resource_extract", "dfm_parse", "event_handler_trace", "generate_lazarus_project", "visual_regression"],
        "reason": "VCL DFM forms often preserve layout and component properties.",
    },
    "pyinstaller_pyside": {
        "name": "extract_pyinstaller_restore_pyside",
        "output_stack": "pyside6",
        "steps": ["resource_extract", "pyinstaller_unpack", "ui_file_extract", "generate_pyside_project", "visual_regression"],
        "reason": "PyInstaller GUI apps often contain Python, .ui, and Qt assets.",
    },
    "android_xml": {
        "name": "extract_apk_layout_generate_android_project",
        "output_stack": "android",
        "steps": ["resource_extract", "layout_manifest_parse", "generate_android_project", "visual_regression"],
        "reason": "Android XML layouts can be converted into an Android Studio project skeleton.",
    },
    "jetpack_compose": {
        "name": "decompile_compose_generate_android_project",
        "output_stack": "android_compose",
        "steps": ["dex_decompile", "compose_signature_trace", "generate_android_project", "visual_regression"],
        "reason": "Compose UI is code-defined and needs decompiler-guided reconstruction.",
    },
    "flutter": {
        "name": "extract_flutter_assets_generate_flutter_project",
        "output_stack": "flutter",
        "steps": ["resource_extract", "flutter_asset_parse", "generate_flutter_project", "visual_regression"],
        "reason": "Flutter apps expose Flutter assets and engine signatures.",
    },
    "react_native": {
        "name": "extract_js_bundle_generate_react_native_project",
        "output_stack": "react_native",
        "steps": ["resource_extract", "js_bundle_extract", "generate_react_native_project", "visual_regression"],
        "reason": "React Native apps often preserve JS bundles and drawable assets.",
    },
    "unity": {
        "name": "extract_unity_assets_generate_unity_shell",
        "output_stack": "unity_skeleton",
        "steps": ["resource_extract", "unity_asset_catalog", "generate_unity_shell", "visual_regression"],
        "reason": "Unity UI is usually asset-driven and needs Unity-specific reconstruction.",
    },
    "webview_hybrid": {
        "name": "extract_web_assets_generate_hybrid_project",
        "output_stack": "web_hybrid",
        "steps": ["resource_extract", "web_asset_extract", "generate_hybrid_project", "visual_regression"],
        "reason": "Hybrid apps preserve web assets that can be reconstructed as a web shell.",
    },
    "uikit_storyboard": {
        "name": "extract_storyboard_generate_xcode_project",
        "output_stack": "ios_uikit",
        "steps": ["resource_extract", "storyboard_parse", "generate_xcode_project", "visual_regression"],
        "reason": "UIKit storyboard/xib files preserve native iOS layout metadata.",
    },
    "swiftui": {
        "name": "decompile_swiftui_generate_xcode_project",
        "output_stack": "ios_swiftui",
        "steps": ["resource_extract", "swift_symbol_trace", "generate_xcode_project", "visual_regression"],
        "reason": "SwiftUI is code-defined and needs symbol/decompiler-guided reconstruction.",
    },
    "self_drawn": {
        "name": "visual_reconstruction_with_runtime_behavior_trace",
        "output_stack": "qt_or_pyside6",
        "steps": ["screenshot_capture", "visual_parse", "runtime_trace", "generate_pyside_project", "visual_regression"],
        "reason": "No extractable UI resources were dominant; visual reconstruction has the highest expected fidelity.",
    },
    "unknown": {
        "name": "manual_assisted_visual_reconstruction",
        "output_stack": "pyside6",
        "steps": ["resource_extract", "visual_parse", "generate_pyside_project", "manual_review"],
        "reason": "No strong GUI framework signal was found.",
    },
}


def gui_world_projection(
    *,
    matrix: Iterable[float],
    viewport: Mapping[str, Any],
    out_dir: str | os.PathLike[str],
    points: Iterable[Iterable[float]] | None = None,
    aabbs: Iterable[Any] | None = None,
    matrix_layout: str = "row-major",
    clip_convention: str = "d3d",
    handedness: str = "left-handed",
    reversed_z: bool = False,
    matrix_source: str | Mapping[str, Any] = "explicit-cli-input",
    coordinate_system: str | Mapping[str, Any] = "world",
    metadata: Mapping[str, Any] | None = None,
) -> ToolResult:
    """Project world geometry and persist deterministic GUI evidence."""

    try:
        engine = WorldProjectionEngine(
            matrix,
            matrix_layout=matrix_layout,
            clip_convention=clip_convention,
            handedness=handedness,
            viewport=viewport,
            matrix_source=matrix_source,
            coordinate_system=coordinate_system,
            reversed_z=reversed_z,
        )
        payload = engine.build_artifact(
            points=points,
            aabbs=aabbs,
            metadata=metadata,
        )
        output_root = Path(out_dir).expanduser().resolve()
        gui_dir = output_root if output_root.name.casefold() == "gui" else output_root / "gui"
        artifact_path = gui_dir / "world_projection.json"
        written = write_projection_artifact(artifact_path, payload)
        return ToolResult(
            tool="gui_world_projection",
            status="ok",
            data={
                "status": "ok",
                "artifact_type": payload.get("artifact_type"),
                "summary": payload.get("summary", {}),
                "provenance": payload.get("provenance", {}),
                "artifact_path": written["path"],
                "artifact_sha256": written["sha256"],
                "artifacts": [written["path"], written["hash_path"]],
            },
        )
    except (OSError, TypeError, ValueError) as exc:
        return ToolResult(
            tool="gui_world_projection",
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            data={"status": "failed", "artifacts": []},
        )


def gui_fingerprint(path: str | os.PathLike[str], out_dir: str | os.PathLike[str] | None = None) -> Dict[str, Any]:
    sample = _require_path(path)
    strings = _extract_strings(_read_prefix(sample))
    lower_text = "\n".join(strings).lower()
    names = _container_names(sample)
    names_lower = "\n".join(names).lower()
    combined = f"{lower_text}\n{names_lower}\n{sample.name.lower()}"
    suffix = sample.suffix.lower()
    candidates: Dict[str, Dict[str, Any]] = {}

    def add(framework: str, score: float, evidence: str) -> None:
        item = candidates.setdefault(framework, {"framework": framework, "score": 0.0, "evidence": []})
        item["score"] += score
        if evidence not in item["evidence"]:
            item["evidence"].append(evidence)

    if suffix == ".apk":
        add("android_xml", 2.0, "APK package")
        if "res/layout" in names_lower or "androidmanifest.xml" in names_lower:
            add("android_xml", 3.0, "Android XML layout or manifest resources")
        if "libflutter.so" in names_lower or "flutter_assets" in names_lower:
            add("flutter", 7.0, "Flutter engine/assets present")
        if "index.android.bundle" in names_lower or "react-native" in combined or "reactnative" in combined:
            add("react_native", 6.5, "React Native bundle/signature present")
        if "classes.dex" in names_lower and "compose" in combined:
            add("jetpack_compose", 6.0, "Jetpack Compose signature present")
        if "libunity.so" in names_lower or "assets/bin/data" in names_lower:
            add("unity", 7.0, "Unity runtime/assets present")
        if "webview" in combined or any(name.endswith((".html", ".js", ".css")) for name in names):
            add("webview_hybrid", 2.5, "Embedded web assets or WebView strings")
    elif suffix == ".ipa":
        add("uikit_storyboard", 2.0, "IPA package")
        if ".storyboard" in names_lower or ".xib" in names_lower:
            add("uikit_storyboard", 5.0, "Storyboard/XIB resources present")
        if "swiftui" in combined:
            add("swiftui", 4.0, "SwiftUI signature present")
        if "flutter_assets" in names_lower or "flutter.framework" in names_lower:
            add("flutter", 4.0, "Flutter iOS assets present")
        if "main.jsbundle" in names_lower or "react" in combined:
            add("react_native", 3.5, "React Native iOS bundle/signature present")
        if "unityframework.framework" in names_lower:
            add("unity", 4.0, "UnityFramework present")
    else:
        if "app.asar" in names_lower or "electron" in combined or suffix == ".asar":
            add("electron", 5.0, "Electron/app.asar signature")
        if "presentationframework" in combined or ".baml" in names_lower or ".xaml" in names_lower:
            add("wpf", 5.0, "WPF PresentationFramework/BAML/XAML signature")
        if "system.windows.forms" in combined or "initializecomponent" in combined:
            add("winforms", 4.5, "WinForms InitializeComponent/System.Windows.Forms signature")
        if any(token in combined for token in ("qt5widgets", "qt6widgets", "qwidget", "qmainwindow")) or ".ui" in names_lower:
            add("qt", 4.5, "Qt Widgets/UI signature")
        if "mfc" in combined or "afxwin" in combined:
            add("mfc", 3.8, "MFC/AFX signature")
        if ".dfm" in names_lower or any(token in combined for token in ("tform", "tbutton", "tlabel")):
            add("delphi_vcl", 4.0, "Delphi/VCL DFM or component signature")
        if any(token in combined for token in ("pyinstaller", "_internal", "pyside6", "pyqt5")):
            add("pyinstaller_pyside", 4.0, "PyInstaller/PySide/PyQt signature")
        if any(token in combined for token in ("user32.dll", "createdialog", "dialogboxparam")):
            add("win32_dialog", 3.0, "Win32 dialog/user32 API signature")
        if any(token in combined for token in ("direct2d", "d3d11", "opengl", "skia", "imgui", "bitblt", "gdi32.dll")):
            add("self_drawn", 3.5, "Self-drawn rendering API signature")
        for framework, score, evidence in _pe_gui_signals(sample):
            add(framework, score, evidence)

    if not candidates:
        add("unknown", 0.5, "No strong GUI framework signal found")
    total = sum(float(item["score"]) for item in candidates.values())
    ranked = sorted(candidates.values(), key=lambda item: (-float(item["score"]), item["framework"]))
    best = ranked[0]
    result = {
        "status": "ok",
        "path": str(sample),
        "platform": _detect_platform(sample, lower_text),
        "framework": best["framework"],
        "confidence": _confidence(float(best["score"]), total),
        "evidence": best["evidence"],
        "candidates": [
            {
                "framework": item["framework"],
                "score": round(float(item["score"]), 3),
                "confidence": _confidence(float(item["score"]), total),
                "evidence": item["evidence"],
            }
            for item in ranked
        ],
        "signals": {"suffix": suffix, "container_entry_count": len(names), "string_count_scanned": len(strings)},
    }
    if out_dir:
        gui_dir = Path(out_dir) / "gui"
        gui_dir.mkdir(parents=True, exist_ok=True)
        path_obj = gui_dir / "fingerprint.json"
        _write_json(path_obj, result)
        result["artifacts"] = [{"name": "gui/fingerprint.json", "path": str(path_obj), "kind": "gui-fingerprint"}]
    return result


def gui_resource_extract(path: str | os.PathLike[str], out_dir: str | os.PathLike[str]) -> Dict[str, Any]:
    sample = _require_path(path)
    resource_dir = Path(out_dir) / "gui" / "resources"
    resource_dir.mkdir(parents=True, exist_ok=True)
    extracted_dir = resource_dir / "extracted"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    counts: Counter[str] = Counter()
    entries: list[Dict[str, Any]] = []
    for name in _container_names(sample):
        kind = _resource_kind(name)
        if kind:
            counts[kind] += 1
            entries.append({"path": name, "kind": kind})
    extracted_files, extraction_errors = _extract_container_resources(sample, extracted_dir, entries)
    pe_extracted, pe_extraction_errors = _extract_pe_resources(sample, extracted_dir / "pe")
    extracted_files.extend(pe_extracted)
    extraction_errors.extend(pe_extraction_errors)
    pe_resources = _pe_resource_summary(sample)
    for key, value in pe_resources.items():
        if isinstance(value, int):
            counts[key] += value
    manifest = {
        "status": "ok",
        "path": str(sample),
        "resource_dir": str(resource_dir),
        "extracted_dir": str(extracted_dir),
        "counts": _normalized_counts(counts),
        "entries": entries[:500],
        "pe_resources": pe_resources,
        "extracted_files": extracted_files,
        "extracted_count": len(extracted_files),
        "extraction_errors": extraction_errors,
    }
    manifest_path = resource_dir / "manifest.json"
    _write_json(manifest_path, manifest)
    return {**manifest, "artifacts": [{"name": "gui/resources/manifest.json", "path": str(manifest_path), "kind": "gui-resources"}]}


def gui_strategy_select(
    fingerprint: Mapping[str, Any] | None = None,
    resources: Mapping[str, Any] | None = None,
    runtime_tree: Mapping[str, Any] | None = None,
    visual: Mapping[str, Any] | None = None,
    evidence_graph: Mapping[str, Any] | None = None,
    historical_strategy: Mapping[str, Any] | str | None = None,
    target: str = "auto",
    out_dir: str | os.PathLike[str] | None = None,
) -> Dict[str, Any]:
    fingerprint = fingerprint or {}
    framework = str(fingerprint.get("framework") or "unknown")
    base = dict(STRATEGY_MAP.get(framework) or STRATEGY_MAP["unknown"])
    resource_score = _bounded_count_score(((resources or {}).get("counts") or {}).values())
    runtime_score = 1.0 if (runtime_tree or {}).get("status") == "ok" else 0.0
    visual_score = _bounded_count_score([((visual or {}).get("screenshot_count") or 0), ((visual or {}).get("detected_widget_count") or 0)])
    decompiler_score = 1.0 if framework in {"wpf", "winforms", "mfc", "swiftui", "jetpack_compose"} else 0.35
    historical_score = float((historical_strategy or {}).get("success_rate") or 0) if isinstance(historical_strategy, Mapping) else (0.5 if historical_strategy else 0.0)
    raw = resource_score * 0.35 + runtime_score * 0.25 + visual_score * 0.20 + decompiler_score * 0.10 + historical_score * 0.10
    graph_nodes = evidence_graph.get("nodes") if isinstance(evidence_graph, Mapping) else []
    evidence_graph_node_count = len(graph_nodes) if isinstance(graph_nodes, list) else 0
    try:
        evidence_graph_confidence = float((evidence_graph or {}).get("confidence") or 0.0) if isinstance(evidence_graph, Mapping) else 0.0
    except (TypeError, ValueError):
        evidence_graph_confidence = 0.0
    requested_target = str(target or "auto").strip() or "auto"
    output_stack = base["output_stack"] if requested_target.lower() == "auto" else requested_target
    historical = dict(historical_strategy) if isinstance(historical_strategy, Mapping) else {}
    historical_framework = str(historical.get("framework") or "").lower()
    historical_name = str(historical.get("strategy") or "")
    historical_applied = bool(historical_name and (not historical_framework or historical_framework == framework) and historical_name == base["name"])
    reason = base["reason"]
    if requested_target.lower() != "auto":
        reason = f"{reason} Explicit --gui-target override selects `{requested_target}`."
    elif historical_applied:
        reason = f"{reason} Historical outcome data also recommends this strategy."
    if evidence_graph_node_count:
        reason = f"{reason} Evidence graph contributes {evidence_graph_node_count} normalized control node(s)."
    result = {
        "status": "ok",
        "framework": framework,
        "platform": fingerprint.get("platform") or "unknown",
        "name": base["name"],
        "strategy": base["name"],
        "output_stack": output_stack,
        "requested_target": requested_target,
        "reason": reason,
        "steps": base["steps"],
        "confidence": round(min(0.99, max(float(fingerprint.get("confidence") or 0.0), raw)), 3),
        "score": round(raw, 3),
        "scores": {
            "resource_score": round(resource_score, 3),
            "runtime_tree_score": round(runtime_score, 3),
            "visual_score": round(visual_score, 3),
            "decompiler_score": round(decompiler_score, 3),
            "historical_success_score": round(historical_score, 3),
        },
        "evidence_graph_node_count": evidence_graph_node_count,
        "evidence_graph_confidence": round(max(0.0, min(0.99, evidence_graph_confidence)), 3),
        "historical_recommendation": historical,
        "historical_recommendation_applied": historical_applied,
    }
    if out_dir:
        gui_dir = Path(out_dir) / "gui"
        gui_dir.mkdir(parents=True, exist_ok=True)
        path_obj = gui_dir / "strategy.json"
        _write_json(path_obj, result)
        result["artifacts"] = [{"name": "gui/strategy.json", "path": str(path_obj), "kind": "gui-strategy"}]
    return result


def gui_runtime_probe(
    path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str] | None = None,
    attach_pid: int | None = None,
    adb_path: str | os.PathLike[str] | None = None,
    android_serial: str | None = None,
    ios_provider_command: Iterable[str | os.PathLike[str]] | str | None = None,
) -> ToolResult:
    sample = Path(path)
    data = {
        "path": str(sample),
        "attach_pid": attach_pid,
        "android_serial": android_serial,
        "status": "unavailable",
        "backend": "none",
        "coverage": {"scope": "none", "hierarchy": "none", "properties": []},
        "reason": "runtime UI probe requires an attached or externally managed GUI target",
        "provenance": {"target_executed": False, "attempts": []},
        "window_count": 0,
        "control_count": 0,
        "windows": [],
    }
    status = "unavailable"
    reason = str(data["reason"])
    attempts: list[Dict[str, Any]] = []

    def record_success(result: Mapping[str, Any]) -> None:
        nonlocal status, reason
        data.update(dict(result))
        status = str(result.get("status") or "ok")
        reason = str(result.get("reason") or "runtime UI provider completed")
        attempts.append({"backend": data.get("backend"), "status": status, "reason": reason})

    def record_failure(backend: str, exc: Exception) -> None:
        nonlocal reason
        if isinstance(exc, RuntimeProviderError):
            attempts.append(exc.as_attempt())
            reason = exc.reason
        else:
            reason = f"{type(exc).__name__}: {exc}"
            attempts.append({"backend": backend, "status": "failed", "reason": reason})

    if _is_windows_runtime() and attach_pid:
        try:
            record_success(probe_windows_uia(int(attach_pid)))
        except Exception as exc:  # noqa: BLE001 - UIA is optional and Win32 remains the fallback.
            record_failure(WINDOWS_UIA_BACKEND, exc)
        if status != "ok":
            try:
                data.update(_win32_runtime_tree(int(attach_pid)))
                uia_reason = reason
                reason = f"Windows UI Automation was unavailable ({uia_reason}); used Win32 window enumeration fallback."
                attempts.append({
                    "backend": "win32-enumwindows",
                    "status": "ok",
                    "reason": "EnumWindows and EnumChildWindows completed for the attached process.",
                })
                data["status"] = "ok"
                data["reason"] = reason
                data["coverage"] = {
                    "scope": "attached-process",
                    "hierarchy": "top-level and child HWNDs",
                    "properties": ["handle", "title", "class_name", "visible", "bounds"],
                    "limits": {"windows": 100, "controls_per_window": 500},
                    "limitations": ["No UI Automation ids, semantic control types, enabled state, or offscreen state."],
                }
                data["provenance"] = {
                    "provider": "user32 EnumWindows/EnumChildWindows",
                    "source": "live attached process",
                    "process_id": int(attach_pid),
                    "target_executed": False,
                }
                status = "ok"
            except Exception as exc:  # noqa: BLE001 - runtime probing remains optional.
                record_failure("win32-enumwindows", exc)
                reason = f"Windows runtime UI providers failed: {reason}"
        if status == "ok" and data.get("backend") != WINDOWS_UIA_BACKEND:
            data["backend"] = "win32-enumwindows"
    elif sample.suffix.lower() == ".apk":
        try:
            record_success(_android_runtime_tree(adb_path=adb_path, android_serial=android_serial))
        except Exception as exc:  # noqa: BLE001 - an unavailable emulator must not block static GUI analysis.
            record_failure("android-uiautomator", exc)
            data["setup_hint"] = "Android runtime UI probing requires a connected device/emulator and uiautomator dump support."
            reason = f"Android runtime UI probe unavailable: {reason}"
    elif sample.suffix.lower() == ".ipa":
        command = ios_provider_command
        if command is not None and not isinstance(command, str):
            command = list(command)
        try:
            record_success(probe_ios_accessibility(provider_command=command))
        except Exception as exc:  # noqa: BLE001 - external XCUITest providers remain optional.
            record_failure("ios-accessibility-provider", exc)
            data["setup_hint"] = "On macOS, configure an xcrun/XCUITest accessibility provider command that emits JSON or XML."
            reason = f"iOS runtime UI probe unavailable: {reason}"
    elif _is_windows_runtime():
        data["setup_hint"] = "Pass --attach-pid for a launched Windows target; the probe then enumerates top-level and child Win32 controls."
        reason = "Windows runtime UI probe requires --attach-pid"
    else:
        data["setup_hint"] = "Runtime UI probing requires a launched target plus Windows UIA, uiautomator, or XCUITest."
    data["status"] = status
    data["reason"] = reason
    provenance = dict(data.get("provenance") or {})
    provenance["target_executed"] = False
    provenance["attempts"] = attempts
    data["provenance"] = provenance
    if out_dir:
        gui_dir = Path(out_dir) / "gui"
        gui_dir.mkdir(parents=True, exist_ok=True)
        raw_xml = data.pop("raw_xml", None)
        path_obj = gui_dir / "runtime_tree.json"
        _write_json(path_obj, data)
        data["artifacts"] = [{"name": "gui/runtime_tree.json", "path": str(path_obj), "kind": "gui-runtime-tree"}]
        if isinstance(raw_xml, str) and raw_xml:
            xml_path = gui_dir / "runtime_tree.xml"
            xml_path.write_text(raw_xml, encoding="utf-8")
            data["artifacts"].append({"name": "gui/runtime_tree.xml", "path": str(xml_path), "kind": "gui-runtime-tree"})
    error = None if status == "ok" else reason
    return ToolResult(tool="gui_runtime_probe", status=status, error=error, data=data)


def gui_visual_parse(
    screenshot_dir: str | os.PathLike[str] | None = None,
    out_dir: str | os.PathLike[str] | None = None,
    vlm_provider: Any = None,
    vlm_timeout_seconds: float | None = None,
) -> ToolResult | Dict[str, Any]:
    """Parse screenshots with local tooling and an optional production VLM.

    ``vlm_provider`` accepts the legacy injected callable, a ``module:callable``
    import path, or a JSON-compatible provider configuration mapping. When it
    is omitted the provider loader consults the GUI VLM environment settings.
    """

    screenshots = _screenshot_files(Path(screenshot_dir)) if screenshot_dir else []
    local_visual = _local_visual_parse(screenshots)
    provider_visual = _provider_visual_parse(
        screenshots,
        vlm_provider,
        timeout_seconds=vlm_timeout_seconds,
    )
    text_regions = list(local_visual.get("text_regions") or []) + list(provider_visual.get("text_regions") or [])
    widgets = list(local_visual.get("widgets") or []) + list(provider_visual.get("widgets") or [])
    local_components = local_visual.get("components") if isinstance(local_visual.get("components"), Mapping) else {}
    components = {
        "image_decode": dict(local_components.get("image_decode") or {}),
        "segmentation": dict(local_components.get("segmentation") or {}),
        "ocr": dict(local_components.get("ocr") or {}),
        "vlm": dict(provider_visual.get("component") or {}),
    }
    provider_name = str(components["vlm"].get("provider") or "not_configured")
    status, reason = _visual_parse_outcome(len(screenshots), components)
    data = {
        "schema_version": 1,
        "status": status,
        "reason": reason,
        "screenshot_dir": str(screenshot_dir) if screenshot_dir else None,
        "screenshot_count": len(screenshots),
        "decoded_screenshot_count": int(components["image_decode"].get("succeeded_count") or 0),
        "screenshots": [str(path) for path in screenshots],
        "ocr_text_count": len(text_regions),
        "detected_widget_count": len(widgets),
        "text_regions": text_regions[:500],
        "widgets": widgets[:500],
        "image_metadata": local_visual.get("image_metadata") or [],
        "errors": list(local_visual.get("errors") or []) + list(provider_visual.get("errors") or []),
        "vlm_provider": provider_name,
        "vlm_provenance": dict(components["vlm"].get("provenance") or {}),
        "components": components,
    }
    if out_dir:
        gui_dir = Path(out_dir) / "gui"
        gui_dir.mkdir(parents=True, exist_ok=True)
        path_obj = gui_dir / "visual_parse.json"
        _write_json(path_obj, data)
        data["artifacts"] = [{"name": "gui/visual_parse.json", "path": str(path_obj), "kind": "gui-visual-parse"}]
    if not screenshots:
        return ToolResult(tool="gui_visual_parse", status="unavailable", error=reason, data=data)
    return data


def reconstruct_gui_project(
    path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    gui_analysis: Mapping[str, Any] | None = None,
    *,
    semantic_ir: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    """Generate a GUI reconstruction skeleton and preserve static evidence.

    ``semantic_ir`` is optional for direct callers, but the CLI supplies it so
    the generated project can be statically verified without re-running the
    original sample or any generated code.
    """

    sample = _require_path(path)
    gui_analysis = gui_analysis or {}
    semantic_payload = _normalize_semantic_ir(semantic_ir)
    strategy = gui_analysis.get("strategy") if isinstance(gui_analysis.get("strategy"), Mapping) else {}
    framework = str(gui_analysis.get("framework") or strategy.get("framework") or "unknown")
    output_stack = str(strategy.get("output_stack") or (STRATEGY_MAP.get(framework) or STRATEGY_MAP["unknown"])["output_stack"])
    project_dir = Path(out_dir) / "reconstructed_gui"
    analysis_dir = project_dir / "analysis"
    src_dir = project_dir / "src"
    assets_dir = project_dir / "assets"
    for directory in (analysis_dir, src_dir, assets_dir):
        directory.mkdir(parents=True, exist_ok=True)
    fingerprint = gui_analysis.get("fingerprint") if isinstance(gui_analysis.get("fingerprint"), Mapping) else {
        "platform": gui_analysis.get("platform"),
        "framework": gui_analysis.get("framework"),
        "confidence": gui_analysis.get("confidence"),
        "evidence": gui_analysis.get("evidence") or [],
    }
    runtime_tree = gui_analysis.get("runtime_tree") if isinstance(gui_analysis.get("runtime_tree"), Mapping) else {}
    visual = gui_analysis.get("visual") if isinstance(gui_analysis.get("visual"), Mapping) else {}
    xaml_evidence = gui_analysis.get("xaml_evidence") if isinstance(gui_analysis.get("xaml_evidence"), Mapping) else {}
    evidence_graph = gui_analysis.get("evidence_graph") if isinstance(gui_analysis.get("evidence_graph"), Mapping) else {}
    state_machine = gui_analysis.get("state_machine") if isinstance(gui_analysis.get("state_machine"), Mapping) else {}
    behavior_graph = gui_analysis.get("behavior_graph") if isinstance(gui_analysis.get("behavior_graph"), Mapping) else {}
    files: Dict[str, str] = {
        "analysis/gui_analysis.json": _write_json(analysis_dir / "gui_analysis.json", dict(gui_analysis)),
        "analysis/gui_strategy.json": _write_json(analysis_dir / "gui_strategy.json", dict(strategy)),
        "analysis/gui_fingerprint.json": _write_json(analysis_dir / "gui_fingerprint.json", dict(fingerprint)),
        "analysis/ui_tree.json": _write_json(analysis_dir / "ui_tree.json", dict(runtime_tree)),
        "analysis/visual_parse.json": _write_json(analysis_dir / "visual_parse.json", dict(visual)),
        "analysis/xaml_evidence.json": _write_json(analysis_dir / "xaml_evidence.json", dict(xaml_evidence)),
        "analysis/evidence_graph.json": _write_json(analysis_dir / "evidence_graph.json", dict(evidence_graph)),
        "analysis/state_machine.json": _write_json(analysis_dir / "state_machine.json", dict(state_machine)),
        "analysis/behavior_graph.json": _write_json(analysis_dir / "behavior_graph.json", dict(behavior_graph)),
    }
    renderer: Dict[str, Any] = {}
    renderer_error: str | None = None
    if output_stack == "electron":
        files.update(_write_electron(project_dir, sample))
    elif output_stack == "wpf":
        graph_nodes = evidence_graph.get("nodes") if isinstance(evidence_graph.get("nodes"), list) else []
        if graph_nodes:
            try:
                # Keep the renderer optional at import time so a malformed or
                # missing advanced generator never blocks the baseline pipeline.
                from .gui_wpf import generate_wpf_project

                candidate = generate_wpf_project(project_dir, evidence_graph)
                if isinstance(candidate, Mapping) and candidate.get("status") == "ok":
                    renderer = dict(candidate)
                    generated = candidate.get("generated_files")
                    if isinstance(generated, Mapping):
                        files.update({str(name): str(path_value) for name, path_value in generated.items()})
                else:
                    renderer_error = "evidence-driven WPF renderer returned an unavailable result"
            except Exception as exc:  # noqa: BLE001 - fall back to a buildable WPF shell.
                renderer_error = f"{type(exc).__name__}: {exc}"
        if not renderer:
            files.update(_write_wpf(project_dir))
    elif output_stack == "winforms":
        files.update(_write_winforms(project_dir))
    elif output_stack in {"win32_cpp", "mfc_or_win32_cpp"}:
        files.update(_write_win32(project_dir))
    elif output_stack in {"qt", "qt_cpp"}:
        files.update(_write_qt(project_dir))
    elif output_stack == "delphi_lazarus":
        files.update(_write_lazarus(project_dir))
    elif output_stack == "flutter":
        files.update(_write_flutter(project_dir))
    elif output_stack == "react_native":
        files.update(_write_react_native(project_dir))
    elif output_stack == "unity_skeleton":
        files.update(_write_unity(project_dir))
    elif output_stack in {"web_hybrid", "web"}:
        files.update(_write_web_hybrid(project_dir))
    elif output_stack.startswith("android"):
        files.update(_write_android(project_dir, compose=output_stack == "android_compose"))
    elif output_stack.startswith("ios"):
        files.update(_write_ios(project_dir, swiftui=output_stack == "ios_swiftui"))
    else:
        files.update(_write_pyside(project_dir))
    copied_assets = _copy_gui_assets(gui_analysis, assets_dir)
    for asset in copied_assets:
        files[f"assets/{asset.relative_to(assets_dir).as_posix()}"] = str(asset)
    files["README.md"] = _write(project_dir / "README.md", _render_gui_readme(sample, framework, output_stack, gui_analysis))
    reconstruction_plan = _build_gui_reconstruction_plan(
        framework=framework,
        output_stack=output_stack,
        strategy=strategy,
        source_file=_gui_source_file(files),
        semantic_ir=semantic_payload,
    )
    files["analysis/reconstruction_plan.json"] = _write_json(
        analysis_dir / "reconstruction_plan.json",
        reconstruction_plan,
    )
    if semantic_payload:
        files["analysis/semantic_ir.json"] = _write_json(analysis_dir / "semantic_ir.json", semantic_payload)
    return {
        "status": "ok",
        "project_dir": str(project_dir),
        "framework": framework,
        "output_stack": output_stack,
        "strategy": strategy.get("name") or strategy.get("strategy"),
        "generated_files": list(files.values()),
        "assets_dir": str(assets_dir),
        "asset_count": len(copied_assets),
        "artifacts": [{"name": name, "path": path_value, "kind": "gui-reconstruction"} for name, path_value in sorted(files.items())],
        "renderer": renderer,
        "renderer_error": renderer_error,
        "reconstruction_plan": reconstruction_plan,
        "semantic_ir": _semantic_ir_summary(semantic_payload),
        "stub_only": not bool(renderer),
    }


def gui_visual_regression(
    original_screenshot_dir: str | os.PathLike[str] | None = None,
    reconstructed_screenshot_dir: str | os.PathLike[str] | None = None,
    out_dir: str | os.PathLike[str] | None = None,
) -> ToolResult | Dict[str, Any]:
    originals = _screenshot_files(Path(original_screenshot_dir)) if original_screenshot_dir else []
    reconstructed = _screenshot_files(Path(reconstructed_screenshot_dir)) if reconstructed_screenshot_dir else []
    pair_count = min(len(originals), len(reconstructed))
    pairs = [_visual_pair_metrics(original, rebuilt) for original, rebuilt in zip(originals[:pair_count], reconstructed[:pair_count])]
    valid_pairs = [item for item in pairs if item.get("status") == "ok" and isinstance(item.get("visual_similarity"), (int, float))]
    failed_pairs = [item for item in pairs if item.get("status") != "ok"]
    valid_pair_count = len(valid_pairs)
    failed_pair_count = len(failed_pairs)
    unpaired_original_count = max(0, len(originals) - pair_count)
    unpaired_reconstructed_count = max(0, len(reconstructed) - pair_count)
    visual_similarity = (
        round(sum(float(item["visual_similarity"]) for item in valid_pairs) / valid_pair_count, 3)
        if valid_pair_count
        else None
    )
    style_delta = _average_style_delta([item.get("style_delta") for item in valid_pairs]) if valid_pairs else None
    status, reason = _visual_regression_outcome(
        pair_count=pair_count,
        valid_pair_count=valid_pair_count,
        unpaired_original_count=unpaired_original_count,
        unpaired_reconstructed_count=unpaired_reconstructed_count,
    )
    decode_status = _regression_decode_status(pair_count, valid_pair_count, pairs)
    pair_errors = [str(item.get("error")) for item in failed_pairs if item.get("error")]
    data = {
        "schema_version": 1,
        "status": status,
        "reason": reason,
        "original_screenshot_count": len(originals),
        "reconstructed_screenshot_count": len(reconstructed),
        "pair_count": pair_count,
        "valid_pair_count": valid_pair_count,
        "failed_pair_count": failed_pair_count,
        "unpaired_original_count": unpaired_original_count,
        "unpaired_reconstructed_count": unpaired_reconstructed_count,
        "visual_similarity": visual_similarity,
        "text_match_rate": 0.0,
        "control_match_rate": 0.0,
        "style_delta": style_delta,
        "pairs": pairs,
        "errors": pair_errors,
        "components": {
            "image_decode": {
                "status": decode_status,
                "provider": "Pillow",
                "optional": False,
                "requested_count": pair_count,
                "succeeded_count": valid_pair_count,
                "failed_count": failed_pair_count,
                "reason": _regression_component_reason(decode_status, valid_pair_count, pair_count),
            },
            "visual_comparison": {
                "status": status,
                "provider": "normalized RGB pixel delta",
                "optional": False,
                "requested_count": pair_count,
                "succeeded_count": valid_pair_count,
                "failed_count": failed_pair_count,
                "reason": reason,
            },
        },
    }
    if out_dir:
        gui_dir = Path(out_dir) / "gui"
        gui_dir.mkdir(parents=True, exist_ok=True)
        path_obj = gui_dir / "regression.json"
        _write_json(path_obj, data)
        data["artifacts"] = [{"name": "gui/regression.json", "path": str(path_obj), "kind": "gui-visual-regression"}]
    if not pair_count:
        return ToolResult(tool="gui_visual_regression", status="unavailable", error=reason, data=data)
    return data


def _require_path(path: str | os.PathLike[str]) -> Path:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    return p


def _read_prefix(path: Path, limit: int = 3_000_000) -> bytes:
    if path.is_dir():
        return "\n".join(str(item.relative_to(path)) for item in list(path.rglob("*"))[:2000]).encode("utf-8", errors="replace")
    return path.read_bytes()[:limit]


def _extract_strings(data: bytes, limit: int = 5000) -> list[str]:
    ascii_strings = [m.group(0).decode("utf-8", errors="replace") for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]
    utf16_strings = [m.group(0).decode("utf-16le", errors="ignore") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data)]
    return (ascii_strings + utf16_strings)[:limit]


def _container_names(path: Path) -> list[str]:
    if path.is_dir():
        return [str(item.relative_to(path)).replace("\\", "/") for item in list(path.rglob("*"))[:5000]]
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                return zf.namelist()[:5000]
        except Exception:
            return []
    if path.suffix.lower() == ".asar":
        return [path.name]
    adjacent: list[str] = []
    for directory_name in ("resources", "_internal"):
        directory = path.parent / directory_name
        if not directory.is_dir():
            continue
        adjacent.extend(
            str(item.relative_to(path.parent)).replace("\\", "/")
            for item in list(directory.rglob("*"))[:2500]
        )
    try:
        adjacent.extend(
            item.name
            for item in list(path.parent.iterdir())[:1000]
            if item.is_file() and item.suffix.lower() in {".dll", ".asar", ".ui", ".dfm"}
        )
    except OSError:
        pass
    return list(dict.fromkeys(adjacent))[:5000]


def _resource_kind(name: str) -> str | None:
    lower = str(name).replace("\\", "/").lower()
    suffix = Path(lower).suffix
    if "app.asar" in lower or suffix == ".asar":
        return "asar"
    if suffix == ".ico":
        return "icons"
    if suffix in IMAGE_SUFFIXES:
        return "images"
    if "res/layout" in lower or lower.endswith((".storyboard", ".xib", ".xaml", ".baml", ".ui", ".dfm")):
        return "layouts"
    if lower.endswith(("/strings.xml", ".resx")):
        return "strings"
    if lower.endswith((".html", ".css", ".js")):
        return "web_assets"
    return None


def _extract_container_resources(sample: Path, extracted_dir: Path, entries: Iterable[Mapping[str, Any]]) -> tuple[list[str], list[str]]:
    """Copy selected package resources without trusting archive member paths."""

    selected = [str(item.get("path") or "") for item in entries if item.get("path")]
    if not selected:
        return [], []
    extracted: list[str] = []
    errors: list[str] = []
    extracted_dir.mkdir(parents=True, exist_ok=True)

    def destination(name: str) -> Path | None:
        relative = Path(name.replace("\\", "/"))
        if relative.is_absolute() or any(part in {"", ".", ".."} or ":" in part for part in relative.parts):
            errors.append(f"unsafe resource path skipped: {name}")
            return None
        target = (extracted_dir / relative).resolve()
        try:
            target.relative_to(extracted_dir.resolve())
        except ValueError:
            errors.append(f"resource path escaped extraction root: {name}")
            return None
        return target

    try:
        if zipfile.is_zipfile(sample):
            with zipfile.ZipFile(sample) as archive:
                for name in selected[:MAX_RESOURCE_FILES]:
                    try:
                        info = archive.getinfo(name)
                    except KeyError:
                        continue
                    if info.is_dir() or info.file_size > MAX_RESOURCE_FILE_BYTES:
                        if info.file_size > MAX_RESOURCE_FILE_BYTES:
                            errors.append(f"resource exceeds {MAX_RESOURCE_FILE_BYTES} bytes: {name}")
                        continue
                    target = destination(name)
                    if target is None:
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
                    extracted.append(str(target))
        elif sample.is_dir():
            for name in selected[:MAX_RESOURCE_FILES]:
                source = sample / Path(name)
                if not source.is_file():
                    continue
                if source.stat().st_size > MAX_RESOURCE_FILE_BYTES:
                    errors.append(f"resource exceeds {MAX_RESOURCE_FILE_BYTES} bytes: {name}")
                    continue
                target = destination(name)
                if target is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                extracted.append(str(target))
        elif sample.is_file():
            for name in selected[:MAX_RESOURCE_FILES]:
                source = sample.parent / Path(name)
                if not source.is_file():
                    continue
                if source.stat().st_size > MAX_RESOURCE_FILE_BYTES:
                    errors.append(f"resource exceeds {MAX_RESOURCE_FILE_BYTES} bytes: {name}")
                    continue
                target = destination(name)
                if target is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                extracted.append(str(target))
    except (OSError, zipfile.BadZipFile) as exc:
        errors.append(f"resource extraction failed: {type(exc).__name__}: {exc}")
    return extracted[:MAX_RESOURCE_FILES], errors[:20]


def _extract_pe_resources(sample: Path, extracted_dir: Path) -> tuple[list[str], list[str]]:
    """Extract raw PE resource blobs when ``pefile`` is available.

    Dialog, menu, string-table, bitmap, and icon data need format-specific
    decoding later, but preserving their original resource blobs here gives
    the selected GUI strategy reproducible input rather than count-only hints.
    """

    if sample.suffix.lower() not in {".exe", ".dll", ".scr"}:
        return [], []
    try:
        import pefile  # type: ignore[import-not-found]
    except Exception:
        return [], []
    extracted: list[str] = []
    errors: list[str] = []
    type_names = {2: "bitmap", 3: "icon", 4: "menu", 5: "dialog", 6: "string"}
    try:
        pe = pefile.PE(str(sample), fast_load=False)
        root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        if root is None:
            return [], []
        extracted_dir.mkdir(parents=True, exist_ok=True)
        for type_entry in getattr(root, "entries", []) or []:
            if len(extracted) >= MAX_RESOURCE_FILES:
                break
            type_id = getattr(type_entry, "id", None)
            type_label = type_names.get(type_id, _safe_resource_component(getattr(type_entry, "name", None) or f"type_{type_id}"))
            for name_entry in getattr(getattr(type_entry, "directory", None), "entries", []) or []:
                if len(extracted) >= MAX_RESOURCE_FILES:
                    break
                name_label = _safe_resource_component(getattr(name_entry, "name", None) or getattr(name_entry, "id", None) or "resource")
                for lang_entry in getattr(getattr(name_entry, "directory", None), "entries", []) or []:
                    if len(extracted) >= MAX_RESOURCE_FILES:
                        break
                    data_entry = getattr(lang_entry, "data", None)
                    struct = getattr(data_entry, "struct", None)
                    if struct is None:
                        continue
                    size = int(getattr(struct, "Size", 0) or 0)
                    if size <= 0 or size > MAX_RESOURCE_FILE_BYTES:
                        if size > MAX_RESOURCE_FILE_BYTES:
                            errors.append(f"PE resource exceeds {MAX_RESOURCE_FILE_BYTES} bytes: {type_label}/{name_label}")
                        continue
                    rva = int(getattr(struct, "OffsetToData", 0) or 0)
                    blob = pe.get_data(rva, size)
                    if not blob:
                        continue
                    language = _safe_resource_component(getattr(lang_entry, "id", None) or "lang")
                    target = extracted_dir / f"{type_label}_{name_label}_{language}.bin"
                    target.write_bytes(blob)
                    extracted.append(str(target))
    except Exception as exc:  # noqa: BLE001 - invalid/non-PE samples must not stop the GUI pipeline.
        return extracted, [*errors, f"PE resource extraction failed: {type(exc).__name__}: {exc}"]
    return extracted, errors


def _safe_resource_component(value: Any) -> str:
    text = str(value or "resource")
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._")
    return text[:80] or "resource"


def _is_windows_runtime() -> bool:
    return os.name == "nt"


def _win32_runtime_tree(process_id: int) -> Dict[str, Any]:
    """Enumerate visible top-level windows and child controls for one PID."""

    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    windows: list[Dict[str, Any]] = []
    control_count = 0
    enum_callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def hwnd_value(hwnd: Any) -> int:
        return int(ctypes.cast(hwnd, ctypes.c_void_p).value or 0)

    def window_info(hwnd: Any) -> Dict[str, Any]:
        length = int(user32.GetWindowTextLengthW(hwnd))
        title = ctypes.create_unicode_buffer(length + 1)
        class_name = ctypes.create_unicode_buffer(256)
        rect = wintypes.RECT()
        user32.GetWindowTextW(hwnd, title, len(title))
        user32.GetClassNameW(hwnd, class_name, len(class_name))
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        return {
            "handle": hex(hwnd_value(hwnd)),
            "title": title.value,
            "class_name": class_name.value,
            "visible": bool(user32.IsWindowVisible(hwnd)),
            "bounds": {
                "left": int(rect.left),
                "top": int(rect.top),
                "width": max(0, int(rect.right - rect.left)),
                "height": max(0, int(rect.bottom - rect.top)),
            },
        }

    @enum_callback
    def top_level_callback(hwnd: Any, _lparam: Any) -> bool:
        nonlocal control_count
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if int(owner.value) != process_id:
            return True
        item = window_info(hwnd)
        controls: list[Dict[str, Any]] = []

        @enum_callback
        def child_callback(child: Any, _child_lparam: Any) -> bool:
            if len(controls) >= 500:
                return False
            controls.append(window_info(child))
            return True

        user32.EnumChildWindows(hwnd, child_callback, 0)
        item["controls"] = controls
        item["control_count"] = len(controls)
        windows.append(item)
        control_count += len(controls)
        return len(windows) < 100

    if not user32.EnumWindows(top_level_callback, 0):
        error = ctypes.get_last_error()
        if error:
            raise ctypes.WinError(error)
    return {"window_count": len(windows), "control_count": control_count, "windows": windows}


def _android_runtime_tree(
    *,
    adb_path: str | os.PathLike[str] | None = None,
    android_serial: str | None = None,
) -> Dict[str, Any]:
    """Compatibility wrapper around the bounded Android adapter."""

    return probe_android_uiautomator(adb_path=adb_path, android_serial=android_serial)


def _android_bounds(value: Any) -> Dict[str, int]:
    numbers = [int(item) for item in re.findall(r"-?\d+", str(value or ""))]
    if len(numbers) != 4:
        return {"left": 0, "top": 0, "width": 0, "height": 0}
    left, top, right, bottom = numbers
    return {"left": left, "top": top, "width": max(0, right - left), "height": max(0, bottom - top)}


def _detect_platform(path: Path, lower_text: str) -> str:
    suffix = path.suffix.lower()
    if suffix == ".apk":
        return "android-apk"
    if suffix == ".ipa":
        return "ios-ipa"
    if suffix in {".exe", ".dll", ".sys"} or lower_text.startswith("mz"):
        return "windows-pe"
    if suffix == ".asar" or path.is_dir():
        return "desktop-package"
    return "unknown"


def _pe_gui_signals(path: Path) -> list[tuple[str, float, str]]:
    if path.suffix.lower() not in {".exe", ".dll", ".scr"}:
        return []
    signals: list[tuple[str, float, str]] = []
    try:
        import pefile  # type: ignore[import-not-found]

        pe = pefile.PE(str(path), fast_load=False)
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry.dll.decode("utf-8", errors="replace").lower() if isinstance(entry.dll, bytes) else str(entry.dll).lower()
            if dll == "user32.dll":
                signals.append(("win32_dialog", 1.5, "imports user32.dll"))
            if dll.startswith("mfc"):
                signals.append(("mfc", 3.0, f"imports {dll}"))
            if dll in {"gdi32.dll", "d2d1.dll", "d3d11.dll", "opengl32.dll"}:
                signals.append(("self_drawn", 1.5, f"imports rendering API {dll}"))
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            resource_types = [str(getattr(entry, "name", None) or getattr(entry, "id", "")) for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries]
            if any(item in {"5", "RT_DIALOG"} for item in resource_types):
                signals.append(("win32_dialog", 3.0, "PE dialog resources present"))
            if resource_types:
                signals.append(("win32_dialog", 0.5, "PE resources present"))
    except Exception:
        return signals
    return signals


def _pe_resource_summary(path: Path) -> Dict[str, Any]:
    if path.suffix.lower() not in {".exe", ".dll", ".scr"}:
        return {}
    try:
        import pefile  # type: ignore[import-not-found]

        pe = pefile.PE(str(path), fast_load=False)
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return {}
        counts: Counter[str] = Counter()
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            value = getattr(entry, "id", None)
            counts[{3: "icons", 2: "images", 5: "dialogs", 4: "menus", 6: "strings"}.get(value, "other")] += 1
        return {**counts, "count": sum(counts.values())}
    except Exception:
        return {}


def _normalized_counts(counts: Mapping[str, int]) -> Dict[str, int]:
    return {key: int(counts.get(key, 0)) for key in ("icons", "images", "dialogs", "menus", "strings", "layouts", "web_assets", "asar", "other")}


def _confidence(score: float, total: float) -> float:
    ratio = score / total if total else 1.0
    return round(min(0.99, max(0.1, ratio * 0.55 + min(0.99, score / 6.0) * 0.45)), 3)


def _bounded_count_score(values: Iterable[Any]) -> float:
    total = 0
    for value in values:
        try:
            total += int(value)
        except (TypeError, ValueError):
            pass
    return min(1.0, total / 10.0)


def _normalize_semantic_ir(value: Mapping[str, Any] | None) -> Dict[str, Any]:
    """Keep copied IR evidence JSON-safe and structurally predictable."""

    if not isinstance(value, Mapping):
        return {}
    try:
        normalized = _json_safe(value)
    except (RecursionError, TypeError, ValueError):
        return {}
    if not isinstance(normalized, Mapping):
        return {}
    result = dict(normalized)
    for field in ("entities", "relations", "capabilities"):
        if field in result and not isinstance(result[field], list):
            result[field] = []
    return result


def _semantic_ir_summary(semantic_ir: Mapping[str, Any]) -> Dict[str, Any]:
    if not semantic_ir:
        return {}
    supplied = semantic_ir.get("summary") if isinstance(semantic_ir.get("summary"), Mapping) else {}
    entities = semantic_ir.get("entities") if isinstance(semantic_ir.get("entities"), list) else []
    relations = semantic_ir.get("relations") if isinstance(semantic_ir.get("relations"), list) else []
    capabilities = semantic_ir.get("capabilities") if isinstance(semantic_ir.get("capabilities"), list) else []
    return {
        "schema_version": semantic_ir.get("schema_version"),
        "entity_count": _safe_count(supplied.get("entity_count"), len(entities)),
        "relation_count": _safe_count(supplied.get("relation_count"), len(relations)),
        "capability_count": _safe_count(supplied.get("capability_count"), len(capabilities)),
    }


def _safe_count(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (OverflowError, TypeError, ValueError):
        return default


def _build_gui_reconstruction_plan(
    *,
    framework: str,
    output_stack: str,
    strategy: Mapping[str, Any],
    source_file: str | None,
    semantic_ir: Mapping[str, Any],
) -> Dict[str, Any]:
    """Describe the static GUI artifact boundary consumed by the verifier."""

    metadata: Dict[str, Any] = {
        "module": "gui",
        "framework": framework,
        "output_stack": output_stack,
    }
    if source_file:
        metadata["module_file"] = source_file
    plan: Dict[str, Any] = {
        "schema_version": 1,
        "kind": "gui-reconstruction",
        "framework": framework,
        "output_stack": output_stack,
        "strategy": strategy.get("name") or strategy.get("strategy"),
        "tasks": [
            {
                "name": "reconstruct_gui",
                "metadata": metadata,
            }
        ],
    }
    summary = _semantic_ir_summary(semantic_ir)
    if summary:
        plan["semantic_ir"] = summary
    return plan


def _gui_source_file(files: Mapping[str, str]) -> str | None:
    source_suffixes = {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".cs",
        ".dart",
        ".fs",
        ".go",
        ".h",
        ".hpp",
        ".html",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".pas",
        ".py",
        ".rs",
        ".swift",
        ".ts",
        ".tsx",
        ".vb",
        ".xaml",
        ".xml",
    }
    candidates = [
        name
        for name in sorted(files, key=str.casefold)
        if not name.startswith("analysis/") and Path(name).suffix.lower() in source_suffixes
    ]
    source_candidates = [name for name in candidates if name.startswith("src/")]
    return (source_candidates or candidates or [None])[0]


def _write_json(path: Path, data: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_json_safe(data), ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    return str(path)


def _json_safe(value: Any, active: set[int] | None = None) -> Any:
    active = active if active is not None else set()
    if isinstance(value, Mapping):
        object_id = id(value)
        if object_id in active:
            return "<cycle>"
        active.add(object_id)
        try:
            return {
                str(key): _json_safe(item, active)
                for key, item in sorted(value.items(), key=lambda item: str(item[0]))
            }
        finally:
            active.discard(object_id)
    if isinstance(value, (list, tuple)):
        object_id = id(value)
        if object_id in active:
            return ["<cycle>"]
        active.add(object_id)
        try:
            return [_json_safe(item, active) for item in value]
        finally:
            active.discard(object_id)
    if isinstance(value, (set, frozenset)):
        return [_json_safe(item, active) for item in sorted(value, key=lambda item: repr(item))]
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if value is None or isinstance(value, (str, int, bool)):
        return value
    return str(value)


def _screenshot_files(path: Path) -> list[Path]:
    if not path.exists() or not path.is_dir():
        return []
    return sorted(item for item in path.iterdir() if item.is_file() and item.suffix.lower() in SCREENSHOT_SUFFIXES)


def _new_visual_component(
    provider: str,
    requested_count: int,
    *,
    optional: bool,
    configured: bool = True,
) -> Dict[str, Any]:
    return {
        "status": "unavailable",
        "provider": provider,
        "optional": optional,
        "configured": configured,
        "available": None,
        "requested_count": requested_count,
        "attempted_count": 0,
        "succeeded_count": 0,
        "failed_count": 0,
        "skipped_count": requested_count,
        "degraded_count": 0,
        "evidence_count": 0,
        "errors": [],
        "reason": "not evaluated",
    }


def _finalize_visual_component(component: Dict[str, Any], *, unavailable_reason: str | None = None) -> None:
    requested = int(component.get("requested_count") or 0)
    attempted = int(component.get("attempted_count") or 0)
    succeeded = int(component.get("succeeded_count") or 0)
    failed = int(component.get("failed_count") or 0)
    degraded = int(component.get("degraded_count") or 0)
    component["skipped_count"] = max(0, requested - attempted)
    if requested <= 0:
        component["status"] = "unavailable"
        component["reason"] = unavailable_reason or "no screenshots were supplied"
    elif unavailable_reason and succeeded <= 0:
        component["status"] = "unavailable"
        component["reason"] = unavailable_reason
    elif succeeded >= requested and failed == 0 and degraded == 0:
        component["status"] = "ok"
        component["reason"] = f"completed for all {requested} screenshot(s)"
    elif succeeded > 0:
        component["status"] = "partial"
        component["reason"] = f"completed for {succeeded} of {requested} screenshot(s)"
    elif attempted > 0 or failed > 0:
        component["status"] = "failed"
        component["reason"] = f"failed for all {attempted or requested} attempted screenshot(s)"
    else:
        component["status"] = "unavailable"
        component["reason"] = "provider was not run"


def _visual_parse_outcome(screenshot_count: int, components: Mapping[str, Mapping[str, Any]]) -> tuple[str, str]:
    if screenshot_count <= 0:
        return "unavailable", "no screenshots supplied; pass --gui-screenshot-dir"
    image_decode = components.get("image_decode") or {}
    segmentation = components.get("segmentation") or {}
    ocr = components.get("ocr") or {}
    vlm = components.get("vlm") or {}
    decoded_count = int(image_decode.get("succeeded_count") or 0)
    provider_evidence_count = int(vlm.get("evidence_count") or 0)
    if decoded_count <= 0:
        if provider_evidence_count > 0:
            return "partial", "VLM evidence was recovered, but no screenshot could be decoded locally"
        return "failed", "no screenshot could be decoded and no valid VLM evidence was recovered"
    if image_decode.get("status") != "ok" or segmentation.get("status") != "ok":
        return "partial", "only part of the screenshot set produced local decode and segmentation evidence"
    if ocr.get("status") in {"failed", "partial"}:
        return "partial", "local image parsing completed, but OCR failed for one or more screenshots"
    if vlm.get("configured") and vlm.get("status") != "ok":
        return "partial", "local image parsing completed, but the configured VLM provider did not complete"
    return "ok", "all screenshots were decoded and segmented without critical errors"


def _local_visual_parse(screenshots: Iterable[Path]) -> Dict[str, Any]:
    """Extract lightweight visual evidence using optional local image tooling."""

    screenshot_list = list(screenshots)
    image_metadata: list[Dict[str, Any]] = []
    text_regions: list[Dict[str, Any]] = []
    widgets: list[Dict[str, Any]] = []
    errors: list[str] = []
    components = {
        "image_decode": _new_visual_component("Pillow", len(screenshot_list), optional=False),
        "segmentation": _new_visual_component("Pillow.ImageFilter.FIND_EDGES", len(screenshot_list), optional=False),
        "ocr": _new_visual_component("pytesseract", len(screenshot_list), optional=True),
    }
    if not screenshot_list:
        for component in components.values():
            _finalize_visual_component(component)
        return {
            "image_metadata": image_metadata,
            "text_regions": text_regions,
            "widgets": widgets,
            "errors": errors,
            "components": components,
        }

    try:
        from PIL import Image, ImageFilter  # type: ignore[import-not-found]
    except Exception as exc:
        reason = f"Pillow unavailable: {type(exc).__name__}: {exc}"
        components["image_decode"]["available"] = False
        components["image_decode"]["errors"].append(reason)
        components["segmentation"]["available"] = False
        _finalize_visual_component(components["image_decode"], unavailable_reason=reason)
        _finalize_visual_component(components["segmentation"], unavailable_reason="segmentation requires Pillow")
        _finalize_visual_component(components["ocr"], unavailable_reason="OCR requires a decodable screenshot")
        return {
            "image_metadata": image_metadata,
            "text_regions": text_regions,
            "widgets": widgets,
            "errors": [reason],
            "components": components,
        }

    components["image_decode"]["available"] = True
    components["segmentation"]["available"] = True
    pytesseract_module: Any = None
    ocr_unavailable_reason: str | None = None
    try:
        import pytesseract  # type: ignore[import-not-found]

        pytesseract_module = pytesseract
        components["ocr"]["available"] = True
    except Exception as exc:
        components["ocr"]["available"] = False
        ocr_unavailable_reason = f"pytesseract unavailable: {type(exc).__name__}: {exc}"
        components["ocr"]["errors"].append(ocr_unavailable_reason)

    for screenshot in screenshot_list:
        image_component = components["image_decode"]
        image_component["attempted_count"] += 1
        try:
            with Image.open(screenshot) as source:
                source.load()
                rgb = source.convert("RGB")
                width, height = rgb.size
        except Exception as exc:  # noqa: BLE001 - corrupt screenshots remain isolated.
            message = f"{screenshot.name}: {type(exc).__name__}: {exc}"
            image_component["failed_count"] += 1
            image_component["errors"].append(message)
            continue

        image_component["succeeded_count"] += 1
        image_component["evidence_count"] += 1
        metadata = {
            "path": str(screenshot),
            "width": width,
            "height": height,
            "mode": rgb.mode,
            "dominant_colors": [],
        }
        image_metadata.append(metadata)
        try:
            segmentation_component = components["segmentation"]
            segmentation_component["attempted_count"] += 1
            try:
                preview = rgb.copy()
                preview.thumbnail((320, 320))
                colors = preview.getcolors(maxcolors=max(1, preview.width * preview.height)) or []
                metadata["dominant_colors"] = [
                    {"rgb": list(color), "count": int(count)}
                    for count, color in sorted(colors, key=lambda item: item[0], reverse=True)[:5]
                ]
                scale_x = width / max(1, preview.width)
                scale_y = height / max(1, preview.height)
                region_count = 0
                for bbox in _edge_regions(preview, image_filter=ImageFilter):
                    x, y, w, h = bbox
                    widgets.append(
                        {
                            "source": "local-edge-segmentation",
                            "type": "visual_region",
                            "bbox": {
                                "x": round(x * scale_x, 1),
                                "y": round(y * scale_y, 1),
                                "width": round(w * scale_x, 1),
                                "height": round(h * scale_y, 1),
                            },
                            "screenshot": str(screenshot),
                        }
                    )
                    region_count += 1
                segmentation_component["succeeded_count"] += 1
                segmentation_component["evidence_count"] += region_count
            except Exception as exc:  # noqa: BLE001 - segmentation failures must not discard decode evidence.
                message = f"{screenshot.name}: {type(exc).__name__}: {exc}"
                segmentation_component["failed_count"] += 1
                segmentation_component["errors"].append(message)

            if pytesseract_module is not None:
                ocr_component = components["ocr"]
                ocr_component["attempted_count"] += 1
                try:
                    regions = _extract_ocr_regions(rgb, screenshot, pytesseract_module)
                    text_regions.extend(regions)
                    ocr_component["succeeded_count"] += 1
                    ocr_component["evidence_count"] += len(regions)
                except Exception as exc:  # noqa: BLE001 - OCR is optional but its state must be explicit.
                    message = f"{screenshot.name}: {type(exc).__name__}: {exc}"
                    ocr_component["failed_count"] += 1
                    ocr_component["errors"].append(message)
                    if _ocr_dependency_unavailable(exc):
                        ocr_component["available"] = False
                        ocr_unavailable_reason = message
                        pytesseract_module = None
        finally:
            rgb.close()

    _finalize_visual_component(components["image_decode"])
    decoded_count = int(components["image_decode"]["succeeded_count"])
    _finalize_visual_component(
        components["segmentation"],
        unavailable_reason="no decodable screenshots available for segmentation" if not decoded_count else None,
    )
    _finalize_visual_component(
        components["ocr"],
        unavailable_reason=("no decodable screenshots available for OCR" if not decoded_count else ocr_unavailable_reason),
    )
    errors.extend(components["image_decode"]["errors"])
    errors.extend(components["segmentation"]["errors"])
    if components["ocr"]["status"] in {"failed", "partial"}:
        errors.extend(components["ocr"]["errors"])
    return {
        "image_metadata": image_metadata,
        "text_regions": text_regions,
        "widgets": widgets,
        "errors": errors,
        "components": components,
    }


def _edge_regions(image: Any, *, image_filter: Any) -> list[tuple[int, int, int, int]]:
    """Return coarse connected edge regions without an OpenCV dependency."""

    edges = image.convert("L").filter(image_filter.FIND_EDGES)
    width, height = edges.size
    values = list(edges.getdata())
    seen = bytearray(width * height)
    regions: list[tuple[int, int, int, int]] = []
    threshold = 64
    min_area = max(12, (width * height) // 2000)
    for start, value in enumerate(values):
        if value < threshold or seen[start]:
            continue
        stack = [start]
        seen[start] = 1
        min_x = max_x = start % width
        min_y = max_y = start // width
        area = 0
        while stack and area < 20_000:
            point = stack.pop()
            x, y = point % width, point // width
            area += 1
            min_x, max_x = min(min_x, x), max(max_x, x)
            min_y, max_y = min(min_y, y), max(max_y, y)
            for neighbor in (point - 1 if x else -1, point + 1 if x + 1 < width else -1, point - width if y else -1, point + width if y + 1 < height else -1):
                if neighbor < 0 or seen[neighbor] or values[neighbor] < threshold:
                    continue
                seen[neighbor] = 1
                stack.append(neighbor)
        region_width = max_x - min_x + 1
        region_height = max_y - min_y + 1
        if area < min_area or region_width < 6 or region_height < 6:
            continue
        if region_width * region_height > width * height * 0.85:
            continue
        regions.append((min_x, min_y, region_width, region_height))
        if len(regions) >= 100:
            break
    return regions


def _ocr_regions(image: Any, screenshot: Path) -> list[Dict[str, Any]]:
    try:
        import pytesseract  # type: ignore[import-not-found]
        return _extract_ocr_regions(image, screenshot, pytesseract)
    except Exception:
        return []


def _extract_ocr_regions(image: Any, screenshot: Path, provider: Any) -> list[Dict[str, Any]]:
    result = provider.image_to_data(image, output_type=provider.Output.DICT)
    regions: list[Dict[str, Any]] = []
    for index, text in enumerate(result.get("text") or []):
        value = str(text or "").strip()
        if not value:
            continue
        try:
            confidence = float((result.get("conf") or [])[index])
        except (IndexError, TypeError, ValueError):
            confidence = 0.0
        regions.append(
            {
                "source": "tesseract",
                "text": value,
                "confidence": round(max(0.0, confidence) / 100.0, 3),
                "bbox": {
                    "x": _list_int(result.get("left"), index),
                    "y": _list_int(result.get("top"), index),
                    "width": _list_int(result.get("width"), index),
                    "height": _list_int(result.get("height"), index),
                },
                "screenshot": str(screenshot),
            }
        )
    return regions


def _ocr_dependency_unavailable(exc: Exception) -> bool:
    name = type(exc).__name__.lower()
    message = str(exc).lower()
    return "notfound" in name or "not found" in message or "not installed" in message


def _list_int(values: Any, index: int) -> int:
    try:
        return int(values[index])
    except (IndexError, TypeError, ValueError):
        return 0


def _provider_visual_parse(
    screenshots: Iterable[Path],
    provider: Any,
    *,
    timeout_seconds: float | None = None,
) -> Dict[str, Any]:
    screenshot_list = list(screenshots)
    text_regions: list[Any] = []
    widgets: list[Any] = []
    errors: list[str] = []
    load_result = load_vlm_provider(provider, timeout_seconds=timeout_seconds)
    load_provenance = dict(load_result.provenance)
    provider_name = str(load_provenance.get("provider") or "not_configured")
    configured = bool(load_provenance.get("configured"))
    component = _new_visual_component(
        provider_name,
        len(screenshot_list),
        optional=True,
        configured=configured,
    )
    component.update(
        {
            "available": load_result.available,
            "load_status": load_result.status,
            "unavailable_count": 0,
            "error_details": [],
            "attempts": [],
            "provenance": load_provenance,
        }
    )
    if not screenshot_list:
        if configured and load_result.status == "failed" and load_result.error is not None:
            error_detail = load_result.error.to_dict()
            component["status"] = "failed"
            component["reason"] = error_detail["message"]
            component["error_details"].append(error_detail)
            component["errors"].append(error_detail["message"])
            errors.append(error_detail["message"])
        else:
            _finalize_visual_component(component)
        return {"text_regions": text_regions, "widgets": widgets, "errors": errors, "component": component}
    if not load_result.available or load_result.provider is None:
        error_detail = load_result.error.to_dict() if load_result.error is not None else {
            "code": "provider_load_failed",
            "status": load_result.status,
            "message": "VLM provider did not load",
        }
        component["status"] = str(error_detail["status"])
        component["reason"] = str(error_detail["message"])
        component["error_details"].append(error_detail)
        if configured:
            component["errors"].append(str(error_detail["message"]))
            errors.append(str(error_detail["message"]))
        return {"text_regions": text_regions, "widgets": widgets, "errors": errors, "component": component}

    loaded_provider = load_result.provider
    for screenshot in screenshot_list:
        component["attempted_count"] += 1
        invocation = loaded_provider.invoke(screenshot)
        attempt: Dict[str, Any] = {
            "screenshot": str(screenshot),
            "status": invocation.status,
            "duration_ms": invocation.duration_ms,
            "provenance": dict(invocation.provenance),
        }
        if invocation.error is not None:
            error_detail = invocation.error.to_dict()
            error_detail["screenshot"] = str(screenshot)
            attempt["error"] = dict(error_detail)
            component["error_details"].append(error_detail)
            message = f"VLM provider {invocation.status} for {screenshot.name}: {invocation.error.message}"
            component["errors"].append(message)
            errors.append(message)
        if invocation.status == "unavailable":
            component["unavailable_count"] += 1
        elif invocation.status == "failed":
            component["failed_count"] += 1
        elif invocation.output is not None:
            response = invocation.output
            screenshot_text = [dict(item) for item in response.get("text_regions") or []]
            screenshot_widgets = [dict(item) for item in response.get("widgets") or []]
            for item in [*screenshot_text, *screenshot_widgets]:
                item["source"] = provider_name
                item["screenshot"] = str(screenshot)
            text_regions.extend(screenshot_text)
            widgets.extend(screenshot_widgets)
            component["succeeded_count"] += 1
            if invocation.status == "partial":
                component["degraded_count"] += 1
            component["evidence_count"] += len(screenshot_text) + len(screenshot_widgets)
            attempt["evidence_count"] = len(screenshot_text) + len(screenshot_widgets)
        component["attempts"].append(attempt)
    if (
        component["unavailable_count"] >= len(screenshot_list)
        and component["failed_count"] == 0
        and component["succeeded_count"] == 0
    ):
        component["status"] = "unavailable"
        component["reason"] = "VLM provider was unavailable for all requested screenshots"
        component["skipped_count"] = 0
    else:
        _finalize_visual_component(component)
    return {"text_regions": text_regions, "widgets": widgets, "errors": errors, "component": component}


def _visual_pair_metrics(original: Path, reconstructed: Path) -> Dict[str, Any]:
    original_hash = _file_hash_evidence(original)
    reconstructed_hash = _file_hash_evidence(reconstructed)
    byte_identical = bool(
        original_hash.get("status") == "ok"
        and reconstructed_hash.get("status") == "ok"
        and original_hash.get("size_bytes") == reconstructed_hash.get("size_bytes")
        and original_hash.get("sha256") == reconstructed_hash.get("sha256")
    )
    pair = {
        "status": "failed",
        "original": str(original),
        "reconstructed": str(reconstructed),
        "visual_similarity": None,
        "style_delta": None,
        "decode": {"status": "failed", "provider": "Pillow"},
        "hash_evidence": {
            "algorithm": "sha256",
            "original": original_hash,
            "reconstructed": reconstructed_hash,
            "byte_identical": byte_identical,
        },
    }
    try:
        from PIL import Image  # type: ignore[import-not-found]

        with Image.open(original) as left_source, Image.open(reconstructed) as right_source:
            left_source.load()
            right_source.load()
            left = left_source.convert("RGB").resize((160, 160))
            right = right_source.convert("RGB").resize((160, 160))
            left_pixels = list(left.getdata())
            right_pixels = list(right.getdata())
        channel_deltas = [0.0, 0.0, 0.0]
        for left_pixel, right_pixel in zip(left_pixels, right_pixels):
            for channel in range(3):
                channel_deltas[channel] += abs(int(left_pixel[channel]) - int(right_pixel[channel]))
        denominator = max(1, len(left_pixels))
        channel_deltas = [value / denominator for value in channel_deltas]
        mean_delta = sum(channel_deltas) / 3.0
        pair.update(
            {
                "status": "ok",
                "visual_similarity": round(max(0.0, 1.0 - mean_delta / 255.0), 3),
                "style_delta": {
                    "mean_channel_delta": round(mean_delta, 3),
                    "red": round(channel_deltas[0], 3),
                    "green": round(channel_deltas[1], 3),
                    "blue": round(channel_deltas[2], 3),
                },
                "decode": {"status": "ok", "provider": "Pillow"},
            }
        )
    except Exception as exc:  # noqa: BLE001 - invalid images are evidence failures, not visual matches.
        error = f"{type(exc).__name__}: {exc}"
        decode_status = "unavailable" if isinstance(exc, (ImportError, ModuleNotFoundError)) else "failed"
        pair["decode"] = {"status": decode_status, "provider": "Pillow", "error": error}
        pair["error"] = error
    return pair


def _file_hash_evidence(path: Path) -> Dict[str, Any]:
    evidence: Dict[str, Any] = {"status": "failed", "path": str(path), "size_bytes": None, "sha256": None}
    try:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
        evidence.update({"status": "ok", "size_bytes": size, "sha256": digest.hexdigest()})
    except OSError as exc:
        evidence["error"] = f"{type(exc).__name__}: {exc}"
    return evidence


def _visual_regression_outcome(
    *,
    pair_count: int,
    valid_pair_count: int,
    unpaired_original_count: int,
    unpaired_reconstructed_count: int,
) -> tuple[str, str]:
    if pair_count <= 0:
        return "unavailable", "original and reconstructed screenshot pairs are required"
    if valid_pair_count <= 0:
        return "failed", "no screenshot pair could be decoded for visual comparison"
    if valid_pair_count < pair_count or unpaired_original_count or unpaired_reconstructed_count:
        return "partial", "only part of the screenshot set produced valid visual comparison pairs"
    return "ok", "all screenshot pairs were decoded and compared"


def _regression_decode_status(pair_count: int, valid_pair_count: int, pairs: Iterable[Mapping[str, Any]]) -> str:
    if pair_count <= 0:
        return "unavailable"
    if valid_pair_count >= pair_count:
        return "ok"
    if valid_pair_count > 0:
        return "partial"
    decode_statuses = [str((item.get("decode") or {}).get("status")) for item in pairs]
    return "unavailable" if decode_statuses and all(status == "unavailable" for status in decode_statuses) else "failed"


def _regression_component_reason(status: str, valid_pair_count: int, pair_count: int) -> str:
    if status == "ok":
        return f"decoded all {pair_count} screenshot pair(s)"
    if status == "partial":
        return f"decoded {valid_pair_count} of {pair_count} screenshot pair(s)"
    if status == "unavailable":
        return "Pillow is unavailable"
    return "no screenshot pair could be decoded"


def _average_style_delta(values: Iterable[Any]) -> Dict[str, Any] | None:
    numeric = [item for item in values if isinstance(item, Mapping) and isinstance(item.get("mean_channel_delta"), (int, float))]
    if not numeric:
        return None
    result: Dict[str, Any] = {"mean_channel_delta": round(sum(float(item.get("mean_channel_delta") or 0.0) for item in numeric) / len(numeric), 3)}
    for channel in ("red", "green", "blue"):
        result[channel] = round(sum(float(item.get(channel) or 0.0) for item in numeric) / len(numeric), 3)
    return result


def _copy_gui_assets(gui_analysis: Mapping[str, Any], assets_dir: Path) -> list[Path]:
    """Copy previously extracted GUI assets into the generated project."""

    candidates: list[Any] = []
    resources = gui_analysis.get("resources")
    if isinstance(resources, Mapping):
        candidates.extend([resources.get("extracted_dir"), resources.get("resource_dir")])
    manifest = gui_analysis.get("resource_manifest")
    if isinstance(manifest, Mapping):
        candidates.extend([manifest.get("extracted_dir"), manifest.get("resource_dir")])
    source_root: Path | None = None
    for value in candidates:
        if not value:
            continue
        candidate = Path(str(value))
        extracted = candidate if candidate.name == "extracted" else candidate / "extracted"
        if extracted.is_dir():
            source_root = extracted
            break
    if source_root is None:
        return []

    copied: list[Path] = []
    for source in source_root.rglob("*"):
        if not source.is_file() or len(copied) >= MAX_RESOURCE_FILES:
            continue
        try:
            relative = source.relative_to(source_root)
        except ValueError:
            continue
        target = assets_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied.append(target)
    return copied


def _write(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


def _write_electron(project_dir: Path, sample: Path) -> Dict[str, str]:
    return {
        "package.json": _write(project_dir / "package.json", '{"name":"reconstructed-gui","main":"main.js","scripts":{"start":"electron ."}}\n'),
        "main.js": _write(project_dir / "main.js", "const {app,BrowserWindow}=require('electron');\napp.whenReady().then(()=>{const win=new BrowserWindow({width:900,height:640});win.loadFile('index.html');});\n"),
        "index.html": _write(project_dir / "index.html", f"<!doctype html><title>Reconstructed GUI</title><main><h1>{sample.name}</h1><p>Evidence-based Electron shell.</p></main>\n"),
    }


def _write_wpf(project_dir: Path) -> Dict[str, str]:
    return {
        "ReconstructedGui.csproj": _write(project_dir / "ReconstructedGui.csproj", '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>WinExe</OutputType><TargetFramework>net8.0-windows</TargetFramework><UseWPF>true</UseWPF></PropertyGroup></Project>\n'),
        "App.xaml": _write(project_dir / "App.xaml", '<Application x:Class="ReconstructedGui.App" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" StartupUri="src/MainWindow.xaml"/>\n'),
        "App.xaml.cs": _write(project_dir / "App.xaml.cs", "namespace ReconstructedGui; public partial class App : System.Windows.Application { }\n"),
        "src/MainWindow.xaml": _write(project_dir / "src" / "MainWindow.xaml", '<Window x:Class="ReconstructedGui.MainWindow" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="Reconstructed GUI" Width="900" Height="640"><Grid><TextBlock Text="GUI reconstructed from evidence" HorizontalAlignment="Center" VerticalAlignment="Center"/></Grid></Window>\n'),
        "src/MainWindow.xaml.cs": _write(project_dir / "src" / "MainWindow.xaml.cs", "namespace ReconstructedGui; public partial class MainWindow : System.Windows.Window { public MainWindow(){ InitializeComponent(); } }\n"),
    }


def _write_winforms(project_dir: Path) -> Dict[str, str]:
    return {
        "ReconstructedGui.csproj": _write(project_dir / "ReconstructedGui.csproj", '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>WinExe</OutputType><TargetFramework>net8.0-windows</TargetFramework><UseWindowsForms>true</UseWindowsForms></PropertyGroup></Project>\n'),
        "src/Program.cs": _write(project_dir / "src" / "Program.cs", "using System.Windows.Forms; ApplicationConfiguration.Initialize(); Application.Run(new MainForm());\n"),
        "src/MainForm.cs": _write(project_dir / "src" / "MainForm.cs", "public class MainForm : Form { public MainForm(){ Text=\"Reconstructed GUI\"; Width=900; Height=640; Controls.Add(new Label{Text=\"GUI reconstructed from evidence\", Dock=DockStyle.Fill}); } }\n"),
    }


def _write_win32(project_dir: Path) -> Dict[str, str]:
    return {
        "CMakeLists.txt": _write(project_dir / "CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)\nproject(reconstructed_gui)\nadd_executable(reconstructed_gui WIN32 src/main.cpp)\n"),
        "src/main.cpp": _write(project_dir / "src" / "main.cpp", '#include <windows.h>\nint WINAPI WinMain(HINSTANCE,HINSTANCE,LPSTR,int){MessageBoxW(nullptr,L"GUI reconstructed from evidence",L"Reconstructed GUI",MB_OK);return 0;}\n'),
    }


def _write_qt(project_dir: Path) -> Dict[str, str]:
    return {
        "CMakeLists.txt": _write(project_dir / "CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)\nproject(reconstructed_gui LANGUAGES CXX)\nfind_package(Qt6 COMPONENTS Widgets REQUIRED)\nqt_add_executable(reconstructed_gui src/main.cpp)\ntarget_link_libraries(reconstructed_gui PRIVATE Qt6::Widgets)\n"),
        "src/main.cpp": _write(project_dir / "src" / "main.cpp", '#include <QApplication>\n#include <QLabel>\nint main(int argc, char **argv) { QApplication app(argc, argv); QLabel label("GUI reconstructed from evidence"); label.resize(900, 640); label.show(); return app.exec(); }\n'),
    }


def _write_lazarus(project_dir: Path) -> Dict[str, str]:
    return {
        "src/ReconstructedGui.lpr": _write(project_dir / "src" / "ReconstructedGui.lpr", "program ReconstructedGui;\nuses Interfaces, Forms, MainUnit;\nbegin RequireDerivedFormResource:=True; Application.Initialize; Application.CreateForm(TMainForm, MainForm); Application.Run; end.\n"),
        "src/MainUnit.pas": _write(project_dir / "src" / "MainUnit.pas", "unit MainUnit;\ninterface\nuses Classes, SysUtils, Forms, Controls, StdCtrls;\ntype TMainForm = class(TForm) public constructor Create(AOwner: TComponent); override; end;\nvar MainForm: TMainForm;\nimplementation\nconstructor TMainForm.Create(AOwner: TComponent); begin inherited Create(AOwner); Caption := 'Reconstructed GUI'; Width := 900; Height := 640; end;\nend.\n"),
    }


def _write_android(project_dir: Path, *, compose: bool = False) -> Dict[str, str]:
    root_build = "plugins { id 'com.android.application' version '8.5.2' apply false }\n"
    app_build = "plugins { id 'com.android.application' }\n\nandroid { namespace 'com.reverseanalyzer.reconstructed'; compileSdk 35\n defaultConfig { applicationId 'com.reverseanalyzer.reconstructed'; minSdk 24; targetSdk 35; versionCode 1; versionName '1.0' } }\n"
    if compose:
        root_build = "plugins { id 'com.android.application' version '8.5.2' apply false; id 'org.jetbrains.kotlin.android' version '1.9.24' apply false }\n"
        app_build = "plugins { id 'com.android.application'; id 'org.jetbrains.kotlin.android' }\n\nandroid { namespace 'com.reverseanalyzer.reconstructed'; compileSdk 35\n defaultConfig { applicationId 'com.reverseanalyzer.reconstructed'; minSdk 24; targetSdk 35; versionCode 1; versionName '1.0' }\n buildFeatures { compose true }\n composeOptions { kotlinCompilerExtensionVersion '1.5.14' } }\n\ndependencies { implementation platform('androidx.compose:compose-bom:2024.06.00'); implementation 'androidx.activity:activity-compose:1.9.1'; implementation 'androidx.compose.material3:material3' }\n"
    files = {
        "settings.gradle": _write(project_dir / "settings.gradle", "rootProject.name='ReconstructedGui'\ninclude ':app'\n"),
        "build.gradle": _write(project_dir / "build.gradle", root_build),
        "app/build.gradle": _write(project_dir / "app" / "build.gradle", app_build),
        "app/src/main/AndroidManifest.xml": _write(project_dir / "app" / "src" / "main" / "AndroidManifest.xml", '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:label="Reconstructed GUI"><activity android:name=".MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity></application></manifest>\n'),
    }
    if compose:
        files["app/src/main/java/com/reverseanalyzer/reconstructed/MainActivity.kt"] = _write(project_dir / "app" / "src" / "main" / "java" / "com" / "reverseanalyzer" / "reconstructed" / "MainActivity.kt", "package com.reverseanalyzer.reconstructed\nimport android.os.Bundle\nimport androidx.activity.ComponentActivity\nimport androidx.activity.compose.setContent\nimport androidx.compose.material3.Text\nclass MainActivity : ComponentActivity() { override fun onCreate(state: Bundle?) { super.onCreate(state); setContent { Text(\"GUI reconstructed from evidence\") } } }\n")
    else:
        files["app/src/main/java/com/reverseanalyzer/reconstructed/MainActivity.java"] = _write(project_dir / "app" / "src" / "main" / "java" / "com" / "reverseanalyzer" / "reconstructed" / "MainActivity.java", "package com.reverseanalyzer.reconstructed;\nimport android.app.Activity; import android.os.Bundle;\npublic class MainActivity extends Activity { @Override public void onCreate(Bundle state) { super.onCreate(state); setContentView(com.reverseanalyzer.reconstructed.R.layout.activity_main); } }\n")
        files["app/src/main/res/layout/activity_main.xml"] = _write(project_dir / "app" / "src" / "main" / "res" / "layout" / "activity_main.xml", '<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android" android:layout_width="match_parent" android:layout_height="match_parent" android:gravity="center"><TextView android:text="GUI reconstructed from evidence" android:layout_width="wrap_content" android:layout_height="wrap_content"/></LinearLayout>\n')
    return files


def _write_flutter(project_dir: Path) -> Dict[str, str]:
    return {
        "pubspec.yaml": _write(project_dir / "pubspec.yaml", "name: reconstructed_gui\ndescription: Evidence-derived Flutter reconstruction\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  flutter:\n    sdk: flutter\n"),
        "lib/main.dart": _write(project_dir / "lib" / "main.dart", "import 'package:flutter/material.dart';\nvoid main() => runApp(const ReconstructedGui());\nclass ReconstructedGui extends StatelessWidget { const ReconstructedGui({super.key}); @override Widget build(BuildContext context) => const MaterialApp(home: Scaffold(body: Center(child: Text('GUI reconstructed from evidence')))); }\n"),
    }


def _write_react_native(project_dir: Path) -> Dict[str, str]:
    return {
        "package.json": _write(project_dir / "package.json", '{"name":"reconstructed-gui","private":true,"scripts":{"start":"react-native start"},"dependencies":{"react":"18.2.0","react-native":"0.75.0"}}\n'),
        "App.js": _write(project_dir / "App.js", "import React from 'react';\nimport {SafeAreaView, Text} from 'react-native';\nexport default function App(){ return <SafeAreaView><Text>GUI reconstructed from evidence</Text></SafeAreaView>; }\n"),
    }


def _write_unity(project_dir: Path) -> Dict[str, str]:
    return {
        "ProjectSettings/ProjectVersion.txt": _write(project_dir / "ProjectSettings" / "ProjectVersion.txt", "m_EditorVersion: 2022.3.0f1\n"),
        "Assets/Scripts/ReconstructedGui.cs": _write(project_dir / "Assets" / "Scripts" / "ReconstructedGui.cs", "using UnityEngine;\npublic class ReconstructedGui : MonoBehaviour { void Start() { Debug.Log(\"GUI reconstructed from evidence\"); } }\n"),
        "Assets/Scenes/Main.unity": _write(project_dir / "Assets" / "Scenes" / "Main.unity", "%YAML 1.1\n# Evidence-derived Unity scene placeholder.\n"),
    }


def _write_web_hybrid(project_dir: Path) -> Dict[str, str]:
    return {
        "index.html": _write(project_dir / "index.html", "<!doctype html><html><head><meta charset=\"utf-8\"><title>Reconstructed GUI</title></head><body><main>GUI reconstructed from evidence</main></body></html>\n"),
        "WEB_SHELL.md": _write(project_dir / "WEB_SHELL.md", "Open index.html in a compatible WebView or package it with the selected hybrid runtime.\n"),
    }


def _write_ios(project_dir: Path, *, swiftui: bool = False) -> Dict[str, str]:
    files = {
        "ios/Main.storyboard": _write(project_dir / "ios" / "Main.storyboard", "<!-- Storyboard skeleton reconstructed from GUI evidence. -->\n"),
        "ios/AppDelegate.swift": _write(project_dir / "ios" / "AppDelegate.swift", "import UIKit\n@main class AppDelegate: UIResponder, UIApplicationDelegate {}\n"),
    }
    if swiftui:
        files["ios/ContentView.swift"] = _write(project_dir / "ios" / "ContentView.swift", "import SwiftUI\nstruct ContentView: View { var body: some View { Text(\"GUI reconstructed from evidence\") } }\n")
    return files


def _write_pyside(project_dir: Path) -> Dict[str, str]:
    return {
        "requirements.txt": _write(project_dir / "requirements.txt", "PySide6>=6.6\n"),
        "src/main.py": _write(project_dir / "src" / "main.py", "from PySide6.QtWidgets import QApplication, QLabel, QMainWindow\napp=QApplication([])\nwin=QMainWindow(); win.setWindowTitle('Reconstructed GUI'); win.resize(900,640); win.setCentralWidget(QLabel('GUI reconstructed from evidence')); win.show(); app.exec()\n"),
    }


def _render_gui_readme(sample: Path, framework: str, output_stack: str, gui_analysis: Mapping[str, Any]) -> str:
    strategy = gui_analysis.get("strategy") if isinstance(gui_analysis.get("strategy"), Mapping) else {}
    evidence = "\n".join(f"- {item}" for item in (gui_analysis.get("evidence") or []))
    return f"""# Reconstructed GUI

- Sample: `{sample.name}`
- Framework: `{framework}`
- Output stack: `{output_stack}`
- Strategy: `{strategy.get('name') or strategy.get('strategy') or 'unknown'}`
- Confidence: `{gui_analysis.get('confidence', 'unknown')}`

## Evidence
{evidence}

This is an evidence-derived GUI reconstruction skeleton. Replace placeholders with validated resource, runtime-tree, visual, and event-handler evidence as analysis deepens.
"""
