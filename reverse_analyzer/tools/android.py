"""Static Android APK analysis helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import zipfile
from typing import Any, Mapping


def android_analyze(path: str | os.PathLike[str], out_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    sample = Path(path)
    if not sample.exists():
        return {"status": "failed", "error": f"sample not found: {sample}", "package_type": "unknown"}
    if sample.suffix.lower() != ".apk":
        return {"status": "unavailable", "package_type": "unknown", "framework": {"name": "unknown"}, "reason": "sample is not an APK"}

    try:
        with zipfile.ZipFile(sample) as archive:
            names = sorted(archive.namelist())
            manifest_bytes = _read_member(archive, "AndroidManifest.xml")
            dex_names = [name for name in names if re.fullmatch(r"classes\d*\.dex", Path(name).name)]
            native_libs = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
            framework = _detect_framework(names, manifest_bytes)
            manifest = _manifest_summary(manifest_bytes)
            resources = _resource_summary(names)
            dex_summary = {"dex_count": len(dex_names), "dex_files": dex_names[:20]}
            native = _native_lib_summary(native_libs)
    except (OSError, zipfile.BadZipFile) as exc:
        return {"status": "failed", "package_type": "apk", "framework": {"name": "unknown"}, "error": str(exc)}

    result: dict[str, Any] = {
        "status": "ok",
        "package_type": "apk",
        "framework": framework,
        "manifest": manifest,
        "resources": resources,
        "dex_summary": dex_summary,
        "native_libs": native,
        "strategy": {
            "name": f"{framework['name']}_static_unpack" if framework.get("name") else "android_static_unpack",
            "key": f"android:{framework.get('name') or 'unknown'}_static_unpack",
            "reason": "Static package structure preserves Android resources, DEX, and native-library evidence.",
        },
        "artifacts": [],
    }
    if out_dir:
        android_dir = Path(out_dir) / "android"
        android_dir.mkdir(parents=True, exist_ok=True)
        files = {
            "android/manifest.json": android_dir / "manifest.json",
            "android/resources.json": android_dir / "resources.json",
            "android/dex_summary.json": android_dir / "dex_summary.json",
            "android/native_libs.json": android_dir / "native_libs.json",
            "android/framework.json": android_dir / "framework.json",
        }
        _write_json(files["android/manifest.json"], manifest)
        _write_json(files["android/resources.json"], resources)
        _write_json(files["android/dex_summary.json"], dex_summary)
        _write_json(files["android/native_libs.json"], native)
        _write_json(files["android/framework.json"], framework)
        result["artifacts"] = [{"name": name, "path": str(path_obj), "kind": "android-analysis"} for name, path_obj in files.items()]
    return result


def _detect_framework(names: list[str], manifest_bytes: bytes) -> dict[str, Any]:
    joined = "\n".join(name.lower() for name in names)
    manifest_text = manifest_bytes.decode("utf-8", errors="ignore").lower()
    candidates: list[tuple[str, float, str]] = []

    def add(name: str, score: float, evidence: str) -> None:
        candidates.append((name, score, evidence))

    if "libflutter.so" in joined or "flutter_assets" in joined:
        add("flutter", 8.0, "libflutter.so/flutter_assets present")
    if "index.android.bundle" in joined or "reactnative" in joined or "react-native" in joined:
        add("react_native", 7.0, "React Native bundle/signature present")
    if "libunity.so" in joined or "assets/bin/data" in joined or "globalgamemanagers" in joined:
        add("unity", 8.0, "Unity runtime/assets present")
    if "androidx.compose" in manifest_text or "compose" in joined:
        add("jetpack_compose", 6.0, "Jetpack Compose signature present")
    if "webview" in manifest_text or any(name.endswith((".html", ".js", ".css")) for name in names):
        add("webview_hybrid", 5.0, "WebView/web assets present")
    if "res/layout/" in joined or "androidmanifest.xml" in joined:
        add("android_xml", 4.0, "Android XML layout/resources present")

    if not candidates:
        return {"name": "unknown", "confidence": 0.0, "evidence": ["No dominant Android framework signal"]}

    scores: dict[str, float] = {}
    evidence: dict[str, list[str]] = {}
    for name, score, reason in candidates:
        scores[name] = scores.get(name, 0.0) + score
        evidence.setdefault(name, [])
        if reason not in evidence[name]:
            evidence[name].append(reason)
    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    total = max(0.1, sum(scores.values()))
    best_name, best_score = ranked[0]
    return {
        "name": best_name,
        "confidence": round(best_score / total, 3),
        "evidence": evidence.get(best_name, []),
        "candidates": [
            {"name": name, "score": round(score, 3), "confidence": round(score / total, 3), "evidence": evidence.get(name, [])}
            for name, score in ranked
        ],
    }


def _manifest_summary(manifest_bytes: bytes) -> dict[str, Any]:
    text = manifest_bytes.decode("utf-8", errors="ignore")
    package_match = re.search(r'package\s*=\s*"([^"]+)"', text)
    activity_matches = re.findall(r"activity", text, flags=re.IGNORECASE)
    permission_matches = re.findall(r"permission", text, flags=re.IGNORECASE)
    return {
        "present": bool(manifest_bytes),
        "package": package_match.group(1) if package_match else None,
        "activity_hint_count": len(activity_matches),
        "permission_hint_count": len(permission_matches),
        "textual": text.lstrip().startswith("<"),
    }


def _resource_summary(names: list[str]) -> dict[str, Any]:
    layouts = [name for name in names if name.startswith("res/layout/") and name.endswith(".xml")]
    drawables = [name for name in names if name.startswith("res/drawable")]
    values = [name for name in names if name.startswith("res/values/") and name.endswith(".xml")]
    assets = [name for name in names if name.startswith("assets/")]
    return {
        "resource_arsc_present": "resources.arsc" in names,
        "layout_count": len(layouts),
        "drawable_count": len(drawables),
        "values_count": len(values),
        "asset_count": len(assets),
        "layout_examples": layouts[:20],
    }


def _native_lib_summary(names: list[str]) -> dict[str, Any]:
    abis = sorted({Path(name).parts[1] for name in names if len(Path(name).parts) >= 3})
    return {
        "count": len(names),
        "abis": abis,
        "libs": names[:40],
    }


def _read_member(archive: zipfile.ZipFile, name: str) -> bytes:
    try:
        return archive.read(name)
    except KeyError:
        return b""


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
