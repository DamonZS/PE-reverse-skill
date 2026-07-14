"""Opt-in live acceptance harness for the production engine runtime provider."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from typing import Any, Mapping

from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.engine_runtime import (
    EngineRuntimeProvider,
    WindowsEngineRuntimeBackend,
)


_FIXTURE_IDS = {
    "unity_mono": "p3-unity-mono-live",
    "unity_il2cpp": "p3-unity-il2cpp-live",
    "unreal": "p3-unreal-live",
}

_CONTRACT_ARTIFACTS = {
    "unity_mono": (
        "engine/runtime-metadata.json",
        "engine/target-identity.json",
        "engine/semantic_ir_fragment.json",
        "engine/execution-proof.json",
    ),
    "unity_il2cpp": (
        "engine/registration.json",
        "engine/target-identity.json",
        "engine/token-native-map.json",
        "engine/execution-proof.json",
    ),
    "unreal": (
        "engine/target-identity.json",
        "engine/gnames.json",
        "engine/gobjects.json",
        "engine/gworld.json",
        "engine/execution-proof.json",
    ),
}

_MODULE_FILTERS = {
    "unity_mono": ["mono", "unityplayer"],
    "unity_il2cpp": ["gameassembly", "unityplayer", "il2cpp"],
    "unreal": ["unrealeditor", "ue4editor", "unreal", "ue4", "ue5"],
}


def live_engine_fixture_enabled(fixture_env: str) -> bool:
    """Return true only for an explicitly configured Windows acceptance run."""

    return bool(
        sys.platform == "win32"
        and os.environ.get("RUN_ENGINE_RUNTIME_WINDOWS_SMOKE") == "1"
        and os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_DIR")
        and os.environ.get(fixture_env)
    )


def run_live_engine_acceptance(
    case: unittest.TestCase,
    *,
    fixture_env: str,
    expected_engine: str,
) -> None:
    """Execute one real target and materialize proof only after all checks pass."""

    case.assertIn(expected_engine, _FIXTURE_IDS)
    fixture_id = _FIXTURE_IDS[expected_engine]
    acceptance_root = _acceptance_root(fixture_id)
    fixture_path = Path(os.environ[fixture_env]).expanduser().resolve()
    case.assertTrue(fixture_path.is_file(), f"engine fixture is not a file: {fixture_path}")
    case.assertEqual(
        fixture_path.suffix.lower(),
        ".exe",
        "live engine fixture must be a Windows executable",
    )

    for relative in _CONTRACT_ARTIFACTS[expected_engine]:
        path = acceptance_root / relative
        if path.is_file():
            path.unlink()

    backend = WindowsEngineRuntimeBackend(max_single_read_bytes=64 * 1024)
    case.assertIs(type(backend), WindowsEngineRuntimeBackend)
    case.assertTrue(backend.available, backend.unavailable_reason)
    case.assertEqual(backend.name, "windows_ctypes_engine_runtime")

    fixture_sha256 = _sha256(fixture_path)
    child = subprocess.Popen(
        [str(fixture_path)],
        cwd=str(fixture_path.parent),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        observed_modules = _wait_for_engine_modules(
            case,
            child,
            backend,
            expected_engine,
        )
        probe = dict(backend.probe_process(child.pid))
        case.assertEqual(probe.get("status"), "ok", probe)
        case.assertTrue(probe.get("accessible"), probe)
        observed_path = Path(str(probe.get("image_path") or "")).resolve()
        case.assertTrue(
            _same_file(fixture_path, observed_path),
            f"started fixture identity changed: {observed_path}",
        )

        provider = EngineRuntimeProvider(
            backend,
            platform_name="win32",
            max_total_read_bytes=64 * 1024 * 1024,
            max_module_read_bytes=16 * 1024 * 1024,
            max_single_read_bytes=64 * 1024,
            max_modules=128,
            max_evidence=4096,
            max_export_names=4096,
        )
        case.assertIs(provider.backend, backend)
        target = TargetIdentity(
            kind="controlled_engine_fixture",
            pid=child.pid,
            path=str(fixture_path),
            sha256=fixture_sha256,
            display_name=fixture_path.name,
        )
        request = CapabilityRequest(
            capability="engine_runtime",
            action="analyze",
            target=target,
            params={
                "scan_all_modules": False,
                "module_names": _MODULE_FILTERS[expected_engine],
                "include_exports": True,
                "include_utf16": True,
                "max_modules": 128,
                "max_total_read_bytes": 64 * 1024 * 1024,
                "max_module_read_bytes": 16 * 1024 * 1024,
                "max_single_read_bytes": 64 * 1024,
                "max_evidence": 4096,
                "max_export_names": 4096,
            },
            session_id=f"{fixture_id}-{child.pid}",
            provenance={
                "source": "p3-engine-acceptance",
                "evidence_class": "live_host_proof",
                "fixture_id": fixture_id,
                "backend": backend.name,
            },
        )
        plan = provider.plan(request)
        validation = provider.validate(plan)
        case.assertTrue(validation.ok, validation.errors)
        result = provider.execute(plan)
        case.assertEqual(result.status, "ok", result.report_section)

        operation = dict(result.report_section.get("operation") or {})
        case.assertIn(expected_engine, operation.get("detected_engines") or [])
        usage = dict(operation.get("read_usage") or {})
        case.assertGreater(int(usage.get("call_count") or 0), 0)
        case.assertGreater(int(usage.get("returned_bytes") or 0), 0)
        case.assertFalse(bool(operation.get("side_effects")))
        case.assertGreater(len(observed_modules), 0)

        bundle = provider.collect_artifacts(result, acceptance_root)
        case.assertTrue(bundle.artifacts)
        for artifact in bundle.artifacts:
            case.assertTrue((acceptance_root / artifact.path).is_file())

        target_identity = {
            **target.to_dict(),
            "observed_image_path": str(observed_path),
            "provider": provider.provider_name,
            "backend": backend.name,
            "evidence_class": "live_host_proof",
        }
        payloads = _engine_payloads(
            case,
            expected_engine=expected_engine,
            fixture_id=fixture_id,
            target_identity=target_identity,
            operation=operation,
            report=result.report_section,
        )
        payloads["engine/target-identity.json"] = target_identity

        for relative, payload in payloads.items():
            _write_json_atomic(acceptance_root / relative, payload)

        _write_json_atomic(
            acceptance_root / "engine/execution-proof.json",
            {
                "schema_version": 1,
                "status": "ok",
                "fixture_id": fixture_id,
                "provider": provider.provider_name,
                "backend": backend.name,
                "evidence_class": "live_host_proof",
                "executed_tests": 1,
                "skipped_tests": 0,
                "live_operations": int(usage["call_count"]),
                "actions": ["probe_process", "enumerate_modules", "read_process_memory"],
                "target": target_identity,
                "provenance": {
                    "source": "production-windows-engine-runtime",
                    "fixture_path": str(fixture_path),
                    "fixture_sha256": fixture_sha256,
                },
            },
        )
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)


def _acceptance_root(fixture_id: str) -> Path:
    authorized_root = Path(
        os.environ["REVERSE_ANALYZER_ACCEPTANCE_DIR"]
    ).expanduser().resolve()
    configured_run = str(
        os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or ""
    ).strip()
    if not configured_run:
        if not authorized_root.is_dir():
            raise AssertionError(
                "REVERSE_ANALYZER_ACCEPTANCE_DIR must name an existing directory"
            )
        return authorized_root

    run_root = Path(configured_run).expanduser().resolve()
    if not run_root.is_dir():
        raise AssertionError("acceptance run directory does not exist")
    if run_root.parent.name != fixture_id:
        raise AssertionError("acceptance run directory does not match the fixture id")
    session_id = str(
        os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_SESSION_ID") or run_root.name
    ).strip()
    if not session_id or session_id != run_root.name:
        raise AssertionError("acceptance session id does not match its run directory")
    try:
        run_root.relative_to(authorized_root)
    except ValueError as exc:
        raise AssertionError(
            "acceptance run directory is outside REVERSE_ANALYZER_ACCEPTANCE_DIR"
        ) from exc
    return run_root


def _wait_for_engine_modules(
    case: unittest.TestCase,
    child: subprocess.Popen[Any],
    backend: WindowsEngineRuntimeBackend,
    expected_engine: str,
) -> list[Mapping[str, Any]]:
    deadline = time.monotonic() + 30.0
    last_modules: list[Mapping[str, Any]] = []
    while time.monotonic() < deadline:
        return_code = child.poll()
        case.assertIsNone(return_code, f"engine fixture exited during startup: {return_code}")
        try:
            last_modules = list(backend.enumerate_modules(child.pid))
        except Exception:
            time.sleep(0.25)
            continue
        if _has_engine_module(last_modules, expected_engine):
            return last_modules
        time.sleep(0.25)
    case.fail(
        f"{expected_engine} modules were not observed in production process; "
        f"modules={[item.get('name') for item in last_modules]}"
    )
    return []


def _has_engine_module(modules: list[Mapping[str, Any]], engine: str) -> bool:
    names = " ".join(
        f"{item.get('name', '')} {item.get('path', '')}".lower() for item in modules
    )
    if engine == "unity_mono":
        return "mono-2.0" in names or "mono.dll" in names
    if engine == "unity_il2cpp":
        return "gameassembly" in names or "il2cpp" in names
    return any(marker in names for marker in ("unrealeditor", "ue4editor", "unreal", "ue4", "ue5"))


def _engine_payloads(
    case: unittest.TestCase,
    *,
    expected_engine: str,
    fixture_id: str,
    target_identity: Mapping[str, Any],
    operation: Mapping[str, Any],
    report: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    provenance = {
        "source": "production-windows-engine-runtime",
        "evidence_class": "live_host_proof",
        "fixture_id": fixture_id,
        "backend": "windows_ctypes_engine_runtime",
    }
    common = {
        "schema_version": 1,
        "status": "ok",
        "target_identity": dict(target_identity),
        "provenance": provenance,
    }
    if expected_engine == "unity_mono":
        components = _runtime_components(operation, expected_engine)
        case.assertTrue(components, "live Mono runtime metadata was not extracted")
        semantic = dict(operation.get("semantic_ir_fragment") or {})
        case.assertTrue(semantic.get("entities"), "live Mono Semantic IR is empty")
        return {
            "engine/runtime-metadata.json": {
                **common,
                "engine": expected_engine,
                "components": components,
                "symbols": list(operation.get("symbols") or []),
                "read_usage": dict(operation.get("read_usage") or {}),
            },
            "engine/semantic_ir_fragment.json": {
                **common,
                "engine": expected_engine,
                "semantic_ir_fragment": semantic,
            },
        }

    if expected_engine == "unity_il2cpp":
        components = _runtime_components(operation, expected_engine)
        validated = [
            item
            for item in components
            if int(item.get("validated_candidate_count") or 0) == 1
            and isinstance(item.get("selected"), Mapping)
        ]
        case.assertEqual(len(validated), 1, "one live IL2CPP registration pair is required")
        selected = dict(validated[0]["selected"])
        mappings = [
            {**dict(mapping), "codegen_module": module.get("name")}
            for module in (selected.get("code_registration") or {}).get("codegen_modules") or []
            for mapping in module.get("method_token_mappings") or []
            if isinstance(mapping, Mapping)
        ]
        case.assertTrue(mappings, "live IL2CPP token-to-native mappings are empty")
        return {
            "engine/registration.json": {
                **common,
                "engine": expected_engine,
                "registration": selected,
                "validated_candidate_count": 1,
            },
            "engine/token-native-map.json": {
                **common,
                "engine": expected_engine,
                "mapping_count": len(mappings),
                "mappings": mappings,
            },
        }

    analysis = dict(report.get("engine_analysis") or {})
    validated_globals = list(
        (analysis.get("runtime_globals") or {}).get("validated") or []
    )
    by_role = {
        str(item.get("role")): dict(item)
        for item in validated_globals
        if isinstance(item, Mapping)
    }
    case.assertTrue(
        {"gnames", "gobjects", "gworld"} <= set(by_role),
        "live Unreal GNames/GObjects/GWorld validation is incomplete",
    )
    return {
        f"engine/{role}.json": {
            **common,
            "engine": expected_engine,
            "role": role,
            "runtime_global": by_role[role],
            "address_resolution": dict(analysis.get("address_resolution") or {}),
        }
        for role in ("gnames", "gobjects", "gworld")
    }


def _runtime_components(
    operation: Mapping[str, Any], expected_engine: str
) -> list[dict[str, Any]]:
    return [
        dict(component)
        for analyzed in operation.get("analyzed_modules") or []
        if isinstance(analyzed, Mapping)
        for component in (analyzed.get("runtime_extraction") or {}).get("components") or []
        if isinstance(component, Mapping) and component.get("engine") == expected_engine
    ]


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return str(left).casefold() == str(right).casefold()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(dict(payload), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
