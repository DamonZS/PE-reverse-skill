"""Static engine fingerprinting helpers for game/application runtimes."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import zipfile
from typing import Any, Iterable, Mapping


_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def engine_analyze(path: str | os.PathLike[str], out_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    sample = Path(path)
    if not sample.exists():
        return {"status": "failed", "error": f"sample not found: {sample}", "engine": "unknown"}

    strings = _extract_strings(_read_prefix(sample))
    names = _container_names(sample)
    sibling_names = _sibling_runtime_names(sample)
    combined = "\n".join([sample.name.lower(), *[item.lower() for item in strings], *[item.lower() for item in names], *[item.lower() for item in sibling_names]])
    suffix = sample.suffix.lower()
    candidates: dict[str, dict[str, Any]] = {}

    def add(engine: str, score: float, evidence: str) -> None:
        item = candidates.setdefault(engine, {"engine": engine, "score": 0.0, "evidence": []})
        item["score"] += score
        if evidence not in item["evidence"]:
            item["evidence"].append(evidence)

    if any(token in combined for token in ("assembly-csharp.dll", "_data/managed/", "mono.dll", "monobleedingedge")):
        add("unity-mono", 7.0, "Unity Mono managed assemblies detected")
    if any(token in combined for token in ("gameassembly.dll", "global-metadata.dat", "il2cpp", "libil2cpp.so")):
        add("unity-il2cpp", 8.0, "IL2CPP metadata/runtime detected")
    if any(token in combined for token in (".pak", ".uasset", ".umap", "ue4", "ue5", "unrealengine", "libue4.so", "libunreal.so")):
        add("unreal", 7.5, "Unreal asset/runtime signatures detected")

    if suffix == ".apk":
        if any(token in combined for token in ("libunity.so", "assets/bin/data", "globalgamemanagers")):
            add("unity-il2cpp", 7.0, "Unity Android runtime/assets detected")
        if any(token in combined for token in (".pak", ".uasset", ".umap", "libue4.so", "libunreal.so")):
            add("unreal", 6.0, "Unreal Android assets/libs detected")
    elif suffix == ".ipa":
        if any(token in combined for token in ("unityframework.framework", "data/globalgamemanagers", "global-metadata.dat")):
            add("unity-il2cpp", 6.5, "Unity iOS framework/assets detected")
        if any(token in combined for token in (".pak", ".uasset", ".umap")):
            add("unreal", 5.5, "Unreal iOS assets detected")

    if not candidates:
        candidates["unknown"] = {"engine": "unknown", "score": 0.1, "evidence": ["No strong engine signal found"]}

    ranked = sorted(candidates.values(), key=lambda item: (-float(item["score"]), item["engine"]))
    total = max(0.1, sum(float(item["score"]) for item in ranked))
    best = ranked[0]
    engine_name = str(best["engine"])
    metadata = _metadata_summary(engine_name, combined, names, sibling_names)
    assets = _asset_summary(names, sibling_names)
    symbols = _symbol_summary(strings, engine_name)
    result: dict[str, Any] = {
        "status": "ok",
        "path": str(sample),
        "platform": _platform_for_suffix(suffix),
        "engine": engine_name,
        "confidence": round(float(best["score"]) / total, 3),
        "evidence": list(best["evidence"]),
        "candidates": [
            {
                "engine": item["engine"],
                "score": round(float(item["score"]), 3),
                "confidence": round(float(item["score"]) / total, 3),
                "evidence": list(item["evidence"]),
            }
            for item in ranked
        ],
        "metadata": metadata,
        "assets": assets,
        "symbols": symbols,
        "strategy": _default_strategy(engine_name),
        "artifacts": [],
    }
    if out_dir:
        engine_dir = Path(out_dir) / "engine"
        engine_dir.mkdir(parents=True, exist_ok=True)
        targets = {
            "engine/fingerprint.json": engine_dir / "fingerprint.json",
            "engine/metadata.json": engine_dir / "metadata.json",
            "engine/assets.json": engine_dir / "assets.json",
            "engine/symbols.json": engine_dir / "symbols.json",
        }
        _write_json(targets["engine/fingerprint.json"], {k: v for k, v in result.items() if k not in {"artifacts"}})
        _write_json(targets["engine/metadata.json"], metadata)
        _write_json(targets["engine/assets.json"], assets)
        _write_json(targets["engine/symbols.json"], symbols)
        result["artifacts"] = [
            {"name": name, "path": str(path_obj), "kind": "engine-analysis"}
            for name, path_obj in targets.items()
        ]
    return result


def _default_strategy(engine_name: str) -> dict[str, Any]:
    mapping = {
        "unity-mono": {"name": "unity_mono_metadata_recovery", "reason": "Managed assemblies preserve high-value symbols and UI/gameplay scripts."},
        "unity-il2cpp": {"name": "unity_il2cpp_metadata_recovery", "reason": "IL2CPP metadata plus GameAssembly/libil2cpp provide recoverable type/method evidence."},
        "unreal": {"name": "unreal_asset_reflection_recovery", "reason": "PAK/UAsset/UMap plus reflection strings preserve engine object relationships."},
        "unknown": {"name": "generic_engine_fingerprint", "reason": "No dominant engine signal found; keep evidence for later fusion."},
    }
    strategy = dict(mapping.get(engine_name, mapping["unknown"]))
    strategy["engine"] = engine_name
    strategy["key"] = f"{engine_name}:{strategy['name']}"
    return strategy


def _metadata_summary(engine_name: str, combined: str, names: list[str], sibling_names: list[str]) -> dict[str, Any]:
    all_names = [*names, *sibling_names]
    managed = sorted({Path(name).name for name in all_names if name.lower().endswith(".dll") and ("managed" in name.lower() or "assembly-csharp" in name.lower())})
    return {
        "managed_assembly_count": len(managed),
        "managed_assemblies": managed[:30],
        "global_metadata_present": "global-metadata.dat" in combined,
        "gameassembly_present": "gameassembly.dll" in combined,
        "mono_present": "mono" in combined,
        "unreal_reflection_strings": sorted({token for token in ("uobject", "uclass", "ufunction", "blueprint", "widget") if token in combined}),
    }


def _asset_summary(names: list[str], sibling_names: list[str]) -> dict[str, Any]:
    all_names = [*names, *sibling_names]
    pak = [name for name in all_names if name.lower().endswith(".pak")]
    uasset = [name for name in all_names if name.lower().endswith(".uasset")]
    umap = [name for name in all_names if name.lower().endswith(".umap")]
    scenes = [name for name in all_names if any(token in name.lower() for token in ("scene", "prefab", "resources.assets", "globalgamemanagers"))]
    return {
        "pak_count": len(pak),
        "uasset_count": len(uasset),
        "umap_count": len(umap),
        "scene_like_asset_count": len(scenes),
        "asset_examples": sorted((pak + uasset + umap + scenes))[:40],
    }


def _symbol_summary(strings: Iterable[str], engine_name: str) -> dict[str, Any]:
    values = list(strings)
    interesting: list[str] = []
    for value in values:
        text = value.strip()
        if not text:
            continue
        if engine_name.startswith("unity") and any(token in text for token in ("MonoBehaviour", "ScriptableObject", "Assembly-CSharp", "UnityEngine", "Canvas", "RectTransform")):
            interesting.append(text)
        elif engine_name == "unreal" and any(token in text for token in ("UObject", "UClass", "UFunction", "Blueprint", "WidgetBlueprint", "AActor")):
            interesting.append(text)
    return {
        "recovered_symbol_count": len(interesting),
        "recovered_symbols": interesting[:40],
    }


def _platform_for_suffix(suffix: str) -> str:
    if suffix == ".apk":
        return "android-apk"
    if suffix == ".ipa":
        return "ios-ipa"
    if suffix in {".exe", ".dll"}:
        return "windows-pe"
    return "unknown"


def _read_prefix(path: Path, limit: int = 2 * 1024 * 1024) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def _extract_strings(data: bytes) -> list[str]:
    ascii_strings = [match.group(0).decode("ascii", errors="ignore") for match in _PRINTABLE_RE.finditer(data)]
    utf16_strings = [match.group(0).decode("utf-16le", errors="ignore") for match in _UTF16LE_RE.finditer(data)]
    merged = ascii_strings + utf16_strings
    seen: set[str] = set()
    result: list[str] = []
    for item in merged:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result[:2000]


def _container_names(path: Path) -> list[str]:
    suffix = path.suffix.lower()
    if suffix not in {".apk", ".ipa", ".zip", ".jar"}:
        return []
    try:
        with zipfile.ZipFile(path) as archive:
            return sorted(archive.namelist())[:4000]
    except (OSError, zipfile.BadZipFile):
        return []


def _sibling_runtime_names(sample: Path) -> list[str]:
    results: list[str] = []
    candidates = [
        sample.parent / f"{sample.stem}_Data",
        sample.parent / "Managed",
        sample.parent / "Metadata",
        sample.parent / "Content",
        sample.parent / "Paks",
    ]
    for root in candidates:
        if not root.exists():
            continue
        try:
            for child in sorted(root.rglob("*")):
                if child.is_file():
                    results.append(str(child.relative_to(sample.parent)).replace("\\", "/"))
                    if len(results) >= 4000:
                        return results
        except OSError:
            continue
    return results


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
