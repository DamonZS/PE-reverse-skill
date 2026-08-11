"""Command-line entry points for the PE migration scaffold."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

try:
    from .acceptance import (
        AcceptanceError,
        list_acceptance_fixtures,
        load_acceptance_records,
        merge_acceptance_records,
        run_acceptance_fixture,
        verify_acceptance_record,
    )
    from .config import AnalyzerConfig, ensure_runtime_dirs, load_config, write_default_knowledge
    from .coverage import audit_capability_coverage
    from .core.audit import CapabilityAuditBuilder, summarize_audit_records
    from .core.capabilities.knowledge import record_capability_lifecycle_outcome
    from .core.capabilities.models import (
        CapabilityArtifact,
        CapabilityArtifactBundle,
        CapabilityExecutionResult,
        CapabilityPlan,
        CapabilityRequest,
        CapabilityRollbackResult,
        CapabilityValidation,
        TargetIdentity,
    )
    from .core.integration import finalize_platform_core
    from .dashboard import build_dashboard, serve_dashboard
    from .environment_validation import validate_external_environment, write_environment_report
    from .knowledge import KnowledgeBase
    from .skills import SkillCatalog
    from .providers import RuleBasedProvider, build_default_registry
    from .platform_catalog import build_platform_catalog
    from .runtime import ExperimentStore, SessionStore, TraceLogger
    from .tools import frida_install_guide, ghidra_install_guide, procmon_install_guide, register_builtin_tools
    from .tools.android import android_java_decompile
except ImportError:  # Allows direct script execution while package-level migration is incomplete.
    from config import AnalyzerConfig, ensure_runtime_dirs, load_config, write_default_knowledge

    CapabilityAuditBuilder = None  # type: ignore[assignment]
    audit_capability_coverage = None  # type: ignore[assignment]
    record_capability_lifecycle_outcome = None  # type: ignore[assignment]
    CapabilityArtifact = None  # type: ignore[assignment]
    CapabilityArtifactBundle = None  # type: ignore[assignment]
    CapabilityExecutionResult = None  # type: ignore[assignment]
    CapabilityPlan = None  # type: ignore[assignment]
    CapabilityRequest = None  # type: ignore[assignment]
    CapabilityRollbackResult = None  # type: ignore[assignment]
    CapabilityValidation = None  # type: ignore[assignment]
    TargetIdentity = None  # type: ignore[assignment]
    summarize_audit_records = None  # type: ignore[assignment]
    KnowledgeBase = None  # type: ignore[assignment]
    SkillCatalog = None  # type: ignore[assignment]
    finalize_platform_core = None  # type: ignore[assignment]
    RuleBasedProvider = None  # type: ignore[assignment]
    build_default_registry = None  # type: ignore[assignment]
    build_platform_catalog = None  # type: ignore[assignment]
    ExperimentStore = None  # type: ignore[assignment]
    SessionStore = None  # type: ignore[assignment]
    TraceLogger = None  # type: ignore[assignment]
    build_dashboard = None  # type: ignore[assignment]
    serve_dashboard = None  # type: ignore[assignment]
    validate_external_environment = None  # type: ignore[assignment]
    write_environment_report = None  # type: ignore[assignment]
    AcceptanceError = ValueError  # type: ignore[assignment,misc]
    list_acceptance_fixtures = None  # type: ignore[assignment]
    load_acceptance_records = None  # type: ignore[assignment]
    merge_acceptance_records = None  # type: ignore[assignment]
    run_acceptance_fixture = None  # type: ignore[assignment]
    verify_acceptance_record = None  # type: ignore[assignment]
    frida_install_guide = None  # type: ignore[assignment]
    ghidra_install_guide = None  # type: ignore[assignment]
    procmon_install_guide = None  # type: ignore[assignment]
    register_builtin_tools = None  # type: ignore[assignment]
    android_java_decompile = None  # type: ignore[assignment]


def android_decompile_command(args: argparse.Namespace) -> int:
    """Expose the existing bounded JADX implementation through the platform CLI."""

    if not callable(android_java_decompile):
        print("Android JADX runtime is unavailable.", file=sys.stderr)
        return 3
    options = {
        "executable": args.jadx,
        "output_dir": args.destination,
        "timeout_seconds": args.timeout,
        "threads": args.threads,
    }
    payload = android_java_decompile(args.sample, args.out, config=options)
    _print_json_payload(payload)
    return 0 if payload.get("status") == "passed" else 3 if payload.get("status") == "unavailable" else 2


_BUILTIN_TOOLS = [
    {
        "name": "file_info",
        "status": "available",
        "description": "Read path, size, suffix, and other basic file metadata.",
    },
    {
        "name": "hash",
        "status": "available",
        "description": "Compute md5 / sha1 / sha256 hashes for the sample.",
    },
    {
        "name": "strings_extract",
        "status": "available",
        "description": "Extract printable ASCII and UTF-16LE strings.",
    },
    {
        "name": "pe_deep_scan",
        "status": "optional-dependency",
        "description": "Deep PE analysis for imports, exports, resources, TLS, overlay, Rich header, IAT anomalies, and shell score.",
    },
    {
        "name": "pe_header_scan",
        "status": "optional-dependency",
        "description": "Parse PE headers, sections, and imports with pefile.",
    },
    {
        "name": "section_entropy_scan",
        "status": "available",
        "description": "Measure section or chunk entropy and highlight suspicious regions.",
    },
    {
        "name": "packer_detect",
        "status": "available",
        "description": "Heuristic packer suspicion scoring from sections, entropy, and strings.",
    },
    {
        "name": "yara_scan",
        "status": "optional-dependency",
        "description": "Run bundled or custom YARA rules and capture matched evidence.",
    },
    {
        "name": "reconstruct_project",
        "status": "available",
        "description": "Generate a compilable reconstruction stub project with artifacts and README.",
    },
    {
        "name": "frida_trace",
        "status": "optional-dependency",
        "description": "Dynamic Windows API trace capture with Frida instrumentation and resumable artifacts.",
    },
    {
        "name": "binary_patch_apply",
        "status": "available",
        "description": "Validate and apply a transactional offline binary patch plan to a new output file with audit and rollback artifacts.",
    },
    {
        "name": "binary_patch_rollback",
        "status": "available",
        "description": "Validate and restore a patched binary to a new output file from a rollback manifest.",
    },
    {
        "name": "validate_patch_plan",
        "status": "available",
        "description": "Validate a binary patch plan, including hashes and payload references, without writing files.",
    },
    {
        "name": "anti_detection_analyze",
        "status": "available",
        "description": "Identify debugger, timing, virtualization, process-probe, and exception-based anti-analysis indicators without producing evasion steps.",
    },
    {
        "name": "debugger_session_import",
        "status": "available",
        "description": "Normalize bounded x64dbg/IDA JSON, WinDbg text, and Windows minidump directories into offline diagnostic evidence.",
    },
    {
        "name": "android_elf_patch_plan",
        "status": "available",
        "description": "Create a hash-bound ARM/AArch64 Android ELF patch plan with PT_LOAD mapping, alignment, relocation, risk, and rollback evidence.",
    },
    {
        "name": "android_elf_patch_verify",
        "status": "available",
        "description": "Re-verify Android ELF patch identity, preimages, virtual-address mapping, relocation risks, and rollback metadata.",
    },
    {
        "name": "dll_proxy_generate",
        "status": "available",
        "description": "Generate an architecture-checked forwarding DLL project inside an explicit copy directory with build, risk, validation, and rollback artifacts.",
    },
    {
        "name": "pe_patch_plan",
        "status": "optional-dependency",
        "description": "Create an explicit-intent PE patch plan with RVA, section, instruction-boundary, CFG, directory, signature, overlay, and rollback checks.",
    },
    {
        "name": "pe_patch_verify",
        "status": "optional-dependency",
        "description": "Re-verify a PE-aware patch plan and refresh its risk and rollback artifacts without modifying the target.",
    },
    {
        "name": "procmon_trace",
        "status": "optional-dependency",
        "description": "Dynamic OS behavior capture with Microsoft Sysinternals Procmon PML/CSV artifacts.",
    },
    {
        "name": "memory_snapshot",
        "status": "optional-runtime",
        "description": "Collect bounded, read-only Windows process module and virtual-memory evidence for an explicitly attached PID.",
    },
    {
        "name": "memory_diff",
        "status": "available",
        "description": "Compare two memory snapshot JSON documents without interacting with a target process.",
    },
    {
        "name": "memory_address_map",
        "status": "available",
        "description": "Map addresses from memory evidence to loaded modules, RVAs, PE sections, and file offsets.",
    },
    {
        "name": "gui_fingerprint",
        "status": "available",
        "description": "Detect GUI platform/framework signals and rank reconstruction candidates.",
    },
    {
        "name": "gui_resource_extract",
        "status": "available",
        "description": "Extract or catalog GUI resources, layouts, package assets, and PE resource hints.",
    },
    {
        "name": "gui_runtime_probe",
        "status": "optional-runtime",
        "description": "Collect a live Windows control tree when a target PID is supplied; Android/iOS adapters degrade gracefully.",
    },
    {
        "name": "gui_visual_parse",
        "status": "available-with-optional-ocr",
        "description": "Parse screenshots into local visual regions, optional OCR text, and optional VLM provider evidence.",
    },
    {
        "name": "gui_strategy_select",
        "status": "available",
        "description": "Fuse static, runtime, visual, decompiler, and historical evidence into a GUI reconstruction strategy.",
    },
    {
        "name": "gui_evidence_graph",
        "status": "available",
        "description": "Merge XAML/resource, runtime, visual, and decompiler observations into a normalized GUI control evidence graph.",
    },
    {
        "name": "gui_state_machine",
        "status": "available",
        "description": "Normalize passive GUI interaction traces plus runtime/visual evidence into deterministic UI states and transitions.",
    },
    {
        "name": "gui_behavior_graph",
        "status": "available",
        "description": "Fuse static, dynamic, GUI, resource, and state-machine observations into a provenance-backed behavior graph.",
    },
    {
        "name": "semantic_ir_build",
        "status": "available",
        "description": "Normalize behavior, decompiler, dynamic, and GUI evidence into a deterministic semantic intermediate representation.",
    },
    {
        "name": "reconstruction_verify",
        "status": "available",
        "description": "Statically validate generated reconstruction artifacts, semantic coverage, and planned module coverage without executing code.",
    },
    {
        "name": "gui_xaml_extract",
        "status": "available",
        "description": "Parse extracted WPF XAML resources into control, layout, and event-handler evidence.",
    },
    {
        "name": "reconstruct_gui_project",
        "status": "available",
        "description": "Generate an evidence-driven GUI reconstruction project using the selected strategy.",
    },
    {
        "name": "gui_visual_regression",
        "status": "available-with-optional-image-metrics",
        "description": "Compare original and reconstructed screenshot pairs and report visual similarity metrics.",
    },
    {
        "name": "gui_world_projection",
        "status": "available",
        "description": "Project world points and AABBs into a viewport with explicit matrix conventions and deterministic evidence artifacts.",
    },
    {
        "name": "engine_analyze",
        "status": "available",
        "description": "Fingerprint Unity/Unreal engine signals and persist static engine evidence artifacts.",
    },
    {
        "name": "android_analyze",
        "status": "available",
        "description": "Statically summarize APK manifest/resources/DEX/native libraries and framework hints.",
    },
    {
        "name": "protocol_analyze",
        "status": "available",
        "description": "Infer passive protocol evidence by fusing strings, dynamic behavior, GUI, and semantic hints.",
    },
    {
        "name": "protocol_capture",
        "status": "available",
        "description": "Import bounded PCAP, PCAPNG, JSON, JSONL, or raw passive protocol evidence.",
    },
    {
        "name": "protocol_infer",
        "status": "available",
        "description": "Infer flow framing, message formats, field statistics, and Protobuf wire shapes.",
    },
    {
        "name": "protocol_summarize",
        "status": "available",
        "description": "Build a stable compact summary from normalized protocol capture and inference evidence.",
    },
    {
        "name": "session-store",
        "status": "planned-or-runtime",
        "description": "Persists ReverseSession state for resumable Flow/Task execution.",
    },
    {
        "name": "trace-logger",
        "status": "planned-or-runtime",
        "description": "Records events, tool calls, and artifacts for reports/dashboard.",
    },
    {
        "name": "knowledge-base",
        "status": "planned-or-runtime",
        "description": "Stores reusable analysis facts, provider notes, and report index data.",
    },
    {
        "name": "experiment-store",
        "status": "available",
        "description": "Persists reproducible analysis plans, state transitions, local-run outcomes, and artifact links.",
    },
    {
        "name": "dashboard",
        "status": "available",
        "description": "Builds an offline reverse-lab command deck from experiments, sessions, knowledge outcomes, and reconstructed-source artifacts.",
    },
]

_RUNTIME_IMPORTS = {
    "AgentLoop": (
        "reverse_analyzer.agent.loop",
        "reverse_analyzer.agent_loop",
        "reverse_analyzer.agents.loop",
    ),
    "ToolExecutor": (
        "reverse_analyzer.tools.executor",
        "reverse_analyzer.tool_executor",
        "reverse_analyzer.tools",
    ),
    "ReportBuilder": (
        "reverse_analyzer.report.builder",
        "reverse_analyzer.report",
        "reverse_analyzer.reports.builder",
        "reverse_analyzer.report_builder",
        "reverse_analyzer.reports",
    ),
}


def _load_symbol(symbol: str) -> Any:
    errors: list[str] = []
    for module_name in _RUNTIME_IMPORTS[symbol]:
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # pragma: no cover - message depends on future modules
            errors.append(f"{module_name}: {exc}")
            continue
        if hasattr(module, symbol):
            return getattr(module, symbol)
        errors.append(f"{module_name}: missing {symbol}")
    joined = "; ".join(errors) or "no candidate modules configured"
    raise RuntimeError(f"{symbol} is not available yet. Tried: {joined}")


def _instantiate(factory: Any, *args: Any, **kwargs: Any) -> Any:
    """Instantiate future classes with duck-typed constructor fallbacks."""

    filtered_kwargs = kwargs
    try:
        import inspect

        signature = inspect.signature(factory)
        if not any(param.kind == param.VAR_KEYWORD for param in signature.parameters.values()):
            filtered_kwargs = {key: value for key, value in kwargs.items() if key in signature.parameters}
    except (TypeError, ValueError):
        filtered_kwargs = kwargs

    attempts = (
        lambda: factory(*args, **filtered_kwargs),
        lambda: factory(**filtered_kwargs),
        lambda: factory(),
    )
    last_error: Exception | None = None
    for attempt in attempts:
        try:
            return attempt()
        except TypeError as exc:
            last_error = exc
    raise RuntimeError(f"Could not instantiate {factory!r}: {last_error}")


def _call_first(obj: Any, names: Iterable[str], *args: Any, **kwargs: Any) -> Any:
    for name in names:
        method = getattr(obj, name, None)
        if callable(method):
            try:
                return method(*args, **kwargs)
            except TypeError:
                return method()
    raise RuntimeError(f"{obj.__class__.__name__} does not expose any of: {', '.join(names)}")


def _load_dynamic_hooks(path: str | Path) -> list[Mapping[str, Any]]:
    """Load a JSON hook plan accepted by the Frida dynamic backend."""

    hook_path = Path(path).resolve()
    try:
        payload = json.loads(hook_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid dynamic hook JSON in {hook_path}: {exc}") from exc
    hooks = payload.get("hooks") if isinstance(payload, Mapping) else payload
    if not isinstance(hooks, list) or not all(isinstance(item, Mapping) for item in hooks):
        raise ValueError("dynamic hook file must contain a JSON list or an object with a 'hooks' list")
    return [dict(item) for item in hooks]


def _load_json_object(path: str | Path, *, label: str) -> dict[str, Any]:
    """Read a BOM-tolerant JSON object for a dedicated CLI command."""

    source = Path(path).expanduser().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise ValueError(f"could not read {label} {source}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {label} {source}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must contain a JSON object: {source}")
    return dict(payload)


def _legacy_result_payload(result: Any) -> dict[str, Any]:
    payload = result.to_dict() if hasattr(result, "to_dict") else result
    if isinstance(payload, Mapping):
        return dict(payload)
    return {"status": "failed", "error": str(payload), "data": {"status": "failed", "artifacts": []}}


def _patch_compatibility_artifacts(result_payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    allowed_kinds = {
        "patched-binary",
        "patch-manifest",
        "patch-rollback",
        "restored-binary",
        "patch-rollback-manifest",
    }
    return [
        dict(item)
        for item in result_payload.get("artifacts") or []
        if isinstance(item, Mapping) and str(item.get("kind") or "") in allowed_kinds
    ]


def _capability_compatibility_error(result_payload: Mapping[str, Any], validation_payload: Any) -> str | None:
    report_section = result_payload.get("report_section")
    if isinstance(report_section, Mapping):
        reason = report_section.get("error") or report_section.get("reason")
        if reason:
            return str(reason)
    provenance = result_payload.get("provenance")
    failure = provenance.get("failure") if isinstance(provenance, Mapping) else None
    if isinstance(failure, Mapping) and failure.get("reason"):
        return str(failure["reason"])
    if isinstance(validation_payload, Mapping):
        errors = validation_payload.get("errors")
        if isinstance(errors, Sequence) and not isinstance(errors, (str, bytes, bytearray)) and errors:
            return "; ".join(str(item) for item in errors)
    return None


def _merge_capability_compatibility_payload(
    capability_payload: Mapping[str, Any],
    compatibility_payload: Mapping[str, Any],
    *,
    preserve_success_status: bool,
    refresh_patch_data: bool,
) -> dict[str, Any]:
    """Expose legacy ToolResult fields alongside the audited capability result."""

    merged = dict(capability_payload)
    for key in ("tool", "status", "error", "data", "metadata", "started_at", "finished_at"):
        if key in compatibility_payload:
            value = compatibility_payload[key]
            merged[key] = dict(value) if key == "data" and isinstance(value, Mapping) else value

    raw_result = capability_payload.get("result")
    result_payload = dict(raw_result) if isinstance(raw_result, Mapping) else {}
    result_status = str(result_payload.get("status") or "failed")
    rollback_payload = capability_payload.get("rollback")
    _, exit_code = _capability_result_outcome(result_payload, rollback_payload)
    compatibility_status = str(compatibility_payload.get("status") or result_status)
    merged["status"] = compatibility_status if preserve_success_status and exit_code == 0 else result_status

    data = merged.get("data")
    if refresh_patch_data and isinstance(data, Mapping):
        refreshed_data = dict(data)
        refreshed_data["status"] = result_status
        refreshed_data["dry_run"] = False if exit_code == 0 else bool(refreshed_data.get("dry_run", True))
        refreshed_data["artifacts"] = _patch_compatibility_artifacts(result_payload) if exit_code == 0 else []
        merged["data"] = refreshed_data
    elif exit_code and isinstance(data, Mapping):
        failed_data = dict(data)
        failed_data["status"] = result_status
        if "valid" in failed_data:
            failed_data["valid"] = False
        merged["data"] = failed_data

    if exit_code:
        merged["error"] = _capability_compatibility_error(
            result_payload,
            capability_payload.get("validation"),
        ) or merged.get("error")

    # Capability fields remain authoritative even when a legacy payload uses
    # similarly named keys such as ``artifacts``.
    for key in (
        "session_id",
        "out_dir",
        "capability",
        "action",
        "provider",
        "validation",
        "result",
        "rollback",
        "artifacts",
    ):
        if key in capability_payload:
            merged[key] = capability_payload[key]
    return merged


def _patch_apply_artifact_dir(out_path: str | Path, artifact_dir: str | Path | None) -> Path:
    destination = Path(out_path).expanduser().resolve()
    return (
        Path(artifact_dir).expanduser().resolve()
        if artifact_dir is not None
        else destination.parent / f"{destination.name}.patch-artifacts"
    )


def _patch_rollback_artifact_dir(out_path: str | Path, artifact_dir: str | Path | None) -> Path:
    destination = Path(out_path).expanduser().resolve()
    return (
        Path(artifact_dir).expanduser().resolve()
        if artifact_dir is not None
        else destination.parent / f"{destination.name}.rollback-artifacts"
    )


def _run_patch_capability(
    *,
    sample: str | Path,
    action: str,
    out_dir: str | Path,
    params: Mapping[str, Any],
    compatibility_payload: Mapping[str, Any],
    preserve_success_status: bool = False,
    refresh_patch_data: bool = False,
    supplemental_artifact_results: Sequence[Mapping[str, Any]] = (),
    entrypoint: str,
) -> int:
    encoded_params = [
        f"{name}={json.dumps(value, ensure_ascii=False, default=str)}"
        for name, value in params.items()
        if value is not None
    ]
    forwarded = argparse.Namespace(
        capability="patch_executor",
        action=action,
        sample=str(sample),
        pid=None,
        out=str(out_dir),
        provider="local_verified_patch",
        param=encoded_params,
        rollback=False,
        compatibility_payload=dict(compatibility_payload),
        compatibility_preserve_success_status=preserve_success_status,
        compatibility_refresh_patch_data=refresh_patch_data,
        supplemental_artifact_results=[dict(item) for item in supplemental_artifact_results],
        entrypoint=entrypoint,
    )
    return capability_run_command(forwarded)


def binary_patch_command(args: argparse.Namespace) -> int:
    """Apply a guarded offline patch plan to a copied output binary."""

    try:
        from .tools import binary_patch_apply_plan
    except ImportError:
        from reverse_analyzer.tools import binary_patch_apply_plan

    preflight = binary_patch_apply_plan(
        args.sample,
        plan=args.plan,
        out_path=args.out,
        apply=False,
        artifact_dir=args.artifact_dir,
    )
    artifact_dir = _patch_apply_artifact_dir(args.out, args.artifact_dir)
    return _run_patch_capability(
        sample=args.sample,
        action="apply" if args.apply else "plan",
        out_dir=artifact_dir,
        params={
            "plan": str(Path(args.plan).expanduser().resolve()),
            "out_path": str(Path(args.out).expanduser().resolve()),
            "artifact_dir": str(artifact_dir),
            "plan_source_path": str(Path(args.plan).expanduser().resolve()),
        },
        compatibility_payload=_legacy_result_payload(preflight),
        refresh_patch_data=bool(args.apply),
        entrypoint="cli.patch-binary.apply",
    )


def binary_patch_rollback_command(args: argparse.Namespace) -> int:
    """Dry-run or restore a patched binary to a separate output path."""

    try:
        from .tools import binary_patch_rollback_plan
    except ImportError:
        from reverse_analyzer.tools import binary_patch_rollback_plan

    preflight = binary_patch_rollback_plan(
        args.patched,
        rollback=args.rollback,
        out_path=args.out,
        apply=False,
        artifact_dir=args.artifact_dir,
    )
    compatibility_payload = _legacy_result_payload(preflight)
    if not args.apply:
        _print_json_payload(compatibility_payload)
        return 0 if getattr(preflight, "status", "failed") in {"ok", "planned"} else 2

    artifact_dir = _patch_rollback_artifact_dir(args.out, args.artifact_dir)
    return _run_patch_capability(
        sample=args.patched,
        action="rollback",
        out_dir=artifact_dir,
        params={
            "rollback": str(Path(args.rollback).expanduser().resolve()),
            "out_path": str(Path(args.out).expanduser().resolve()),
            "artifact_dir": str(artifact_dir),
        },
        compatibility_payload=compatibility_payload,
        refresh_patch_data=True,
        entrypoint="cli.patch-binary.rollback",
    )


def validate_patch_plan_command(args: argparse.Namespace) -> int:
    """Validate a patch plan without creating a patched binary."""

    try:
        from .tools import validate_patch_plan
    except ImportError:
        from reverse_analyzer.tools import validate_patch_plan

    preflight = validate_patch_plan(args.sample, plan=args.plan)
    plan_path = Path(args.plan).expanduser().resolve()
    out_dir = plan_path.parent / f"{plan_path.stem}.validate-session"
    return _run_patch_capability(
        sample=args.sample,
        action="validate",
        out_dir=out_dir,
        params={
            "plan": str(plan_path),
            "artifact_dir": str(out_dir),
        },
        compatibility_payload=_legacy_result_payload(preflight),
        entrypoint="cli.validate-patch-plan",
    )


def pe_patch_plan_command(args: argparse.Namespace) -> int:
    """Build PE-aware planning artifacts from one explicit patch intent."""

    try:
        from .patch import plan_pe_patch
    except ImportError:
        from reverse_analyzer.patch import plan_pe_patch

    requested_out = Path(args.out).resolve()
    patch_dir = requested_out if requested_out.name.casefold() == "patch" else requested_out / "patch"
    result = plan_pe_patch(
        args.sample,
        out_dir=patch_dir,
        strategy=args.strategy,
        offset=args.offset,
        rva=args.rva,
        aob=args.aob,
        replacement=args.replacement,
        occurrence=args.occurrence,
        operation_id=args.operation_id,
    )
    compatibility_payload = _legacy_result_payload(result)
    data = compatibility_payload.get("data")
    plan_path = data.get("plan_path") if isinstance(data, Mapping) else None
    if getattr(result, "status", "failed") != "ok" or not plan_path:
        _print_json_payload(compatibility_payload)
        return 2

    sample_path = Path(args.sample).expanduser().resolve()
    planned_output = patch_dir / f"{sample_path.stem}.patched{sample_path.suffix}"
    return _run_patch_capability(
        sample=sample_path,
        action="plan",
        out_dir=requested_out,
        params={
            "plan": str(Path(str(plan_path)).expanduser().resolve()),
            "out_path": str(planned_output),
            "artifact_dir": str(patch_dir),
            "plan_source_path": str(Path(str(plan_path)).expanduser().resolve()),
        },
        compatibility_payload=compatibility_payload,
        preserve_success_status=True,
        entrypoint="cli.patch.plan",
    )


def pe_patch_verify_command(args: argparse.Namespace) -> int:
    """Re-verify one PE-aware patch plan without writing a binary."""

    try:
        from .patch import verify_pe_patch
    except ImportError:
        from reverse_analyzer.patch import verify_pe_patch

    result = verify_pe_patch(args.sample, plan=args.plan, out_dir=args.out)
    compatibility_payload = _legacy_result_payload(result)
    if getattr(result, "status", "failed") != "ok":
        _print_json_payload(compatibility_payload)
        return 2

    plan_path = Path(args.plan).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve() if args.out else plan_path.parent
    return _run_patch_capability(
        sample=args.sample,
        action="validate",
        out_dir=out_dir,
        params={
            "plan": str(plan_path),
            "artifact_dir": str(out_dir),
            "plan_source_path": str(plan_path),
        },
        compatibility_payload=compatibility_payload,
        preserve_success_status=True,
        entrypoint="cli.patch.verify",
    )


def pe_patch_apply_command(args: argparse.Namespace) -> int:
    """Verify and apply a PE patch plan to an explicit output copy."""

    try:
        from .patch import verify_pe_patch
        from .tools import binary_patch_apply_plan
    except ImportError:
        from reverse_analyzer.patch import verify_pe_patch
        from reverse_analyzer.tools import binary_patch_apply_plan

    plan_path = Path(args.plan).resolve()
    artifact_dir = Path(args.artifact_dir).resolve() if args.artifact_dir else plan_path.parent
    try:
        plan_payload = json.loads(plan_path.read_text(encoding="utf-8-sig"))
        if not isinstance(plan_payload, Mapping):
            raise ValueError("PE patch plan JSON must be an object")
        bound_plan = dict(plan_payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        _print_json_payload(
            {
                "tool": "pe_patch_apply",
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "data": {"status": "failed", "plan_path": str(plan_path), "artifacts": []},
            }
        )
        return 2

    verification = verify_pe_patch(args.sample, plan=bound_plan, out_dir=artifact_dir)
    verification_payload = _legacy_result_payload(verification)
    if getattr(verification, "status", "failed") != "ok":
        _print_json_payload(verification_payload)
        return 2

    preflight = binary_patch_apply_plan(
        args.sample,
        plan=bound_plan,
        out_path=args.out,
        apply=False,
        artifact_dir=artifact_dir,
        plan_source_path=plan_path,
    )
    return _run_patch_capability(
        sample=args.sample,
        action="apply",
        out_dir=artifact_dir,
        params={
            "plan": str(plan_path),
            "out_path": str(Path(args.out).expanduser().resolve()),
            "artifact_dir": str(artifact_dir),
            "plan_source_path": str(plan_path),
        },
        compatibility_payload=_legacy_result_payload(preflight),
        refresh_patch_data=True,
        supplemental_artifact_results=(verification_payload,),
        entrypoint="cli.patch.apply",
    )


def pe_patch_rollback_command(args: argparse.Namespace) -> int:
    """Restore a patched copy using a hash-bound PE rollback plan."""

    try:
        from .tools import binary_patch_rollback_plan
    except ImportError:
        from reverse_analyzer.tools import binary_patch_rollback_plan

    rollback_path = Path(args.rollback_plan).resolve()
    artifact_dir = Path(args.artifact_dir).resolve() if args.artifact_dir else rollback_path.parent
    preflight = binary_patch_rollback_plan(
        args.patched,
        rollback=rollback_path,
        out_path=args.out,
        apply=False,
        artifact_dir=artifact_dir,
    )
    return _run_patch_capability(
        sample=args.patched,
        action="rollback",
        out_dir=artifact_dir,
        params={
            "rollback": str(rollback_path),
            "out_path": str(Path(args.out).expanduser().resolve()),
            "artifact_dir": str(artifact_dir),
        },
        compatibility_payload=_legacy_result_payload(preflight),
        refresh_patch_data=True,
        entrypoint="cli.patch.rollback",
    )


def android_elf_patch_plan_command(args: argparse.Namespace) -> int:
    """Build an audited ARM/AArch64 ELF patch plan from explicit intent."""

    try:
        from .patch import plan_android_elf_patch
    except ImportError:
        from reverse_analyzer.patch import plan_android_elf_patch

    requested_out = Path(args.out).expanduser().resolve()
    patch_dir = requested_out if requested_out.name.casefold() == "patch" else requested_out / "patch"
    result = plan_android_elf_patch(
        args.sample,
        out_dir=patch_dir,
        virtual_address=args.virtual_address,
        file_offset=args.file_offset,
        replacement=args.replacement,
        instruction_mode=args.instruction_mode,
        operation_id=args.operation_id,
    )
    compatibility_payload = _legacy_result_payload(result)
    data = compatibility_payload.get("data")
    plan_path = data.get("plan_path") if isinstance(data, Mapping) else None
    if getattr(result, "status", "failed") != "ok" or not plan_path:
        _print_json_payload(compatibility_payload)
        return 2

    sample_path = Path(args.sample).expanduser().resolve()
    planned_output = patch_dir / f"{sample_path.stem}.patched{sample_path.suffix}"
    return _run_patch_capability(
        sample=sample_path,
        action="plan",
        out_dir=requested_out,
        params={
            "plan": str(Path(str(plan_path)).expanduser().resolve()),
            "out_path": str(planned_output),
            "artifact_dir": str(patch_dir),
            "plan_source_path": str(Path(str(plan_path)).expanduser().resolve()),
        },
        compatibility_payload=compatibility_payload,
        preserve_success_status=True,
        entrypoint="cli.patch.android-elf-plan",
    )


def android_elf_patch_verify_command(args: argparse.Namespace) -> int:
    """Re-verify an Android ELF plan without modifying the target."""

    try:
        from .patch import verify_android_elf_patch
    except ImportError:
        from reverse_analyzer.patch import verify_android_elf_patch

    plan_path = Path(args.plan).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve() if args.out else plan_path.parent
    result = verify_android_elf_patch(args.sample, plan=plan_path, out_dir=out_dir)
    compatibility_payload = _legacy_result_payload(result)
    if getattr(result, "status", "failed") != "ok":
        _print_json_payload(compatibility_payload)
        return 2
    return _run_patch_capability(
        sample=args.sample,
        action="validate",
        out_dir=out_dir,
        params={
            "plan": str(plan_path),
            "artifact_dir": str(out_dir),
            "plan_source_path": str(plan_path),
        },
        compatibility_payload=compatibility_payload,
        preserve_success_status=True,
        entrypoint="cli.patch.android-elf-verify",
    )


def android_elf_patch_apply_command(args: argparse.Namespace) -> int:
    """Verify and apply an Android ELF patch to a separate output copy."""

    try:
        from .patch import verify_android_elf_patch
        from .tools import binary_patch_apply_plan
    except ImportError:
        from reverse_analyzer.patch import verify_android_elf_patch
        from reverse_analyzer.tools import binary_patch_apply_plan

    plan_path = Path(args.plan).expanduser().resolve()
    artifact_dir = Path(args.artifact_dir).expanduser().resolve() if args.artifact_dir else plan_path.parent
    verification = verify_android_elf_patch(args.sample, plan=plan_path, out_dir=artifact_dir)
    verification_payload = _legacy_result_payload(verification)
    if getattr(verification, "status", "failed") != "ok":
        _print_json_payload(verification_payload)
        return 2
    preflight = binary_patch_apply_plan(
        args.sample,
        plan=plan_path,
        out_path=args.out,
        apply=False,
        artifact_dir=artifact_dir,
        plan_source_path=plan_path,
    )
    return _run_patch_capability(
        sample=args.sample,
        action="apply",
        out_dir=artifact_dir,
        params={
            "plan": str(plan_path),
            "out_path": str(Path(args.out).expanduser().resolve()),
            "artifact_dir": str(artifact_dir),
            "plan_source_path": str(plan_path),
        },
        compatibility_payload=_legacy_result_payload(preflight),
        refresh_patch_data=True,
        supplemental_artifact_results=(verification_payload,),
        entrypoint="cli.patch.android-elf-apply",
    )


def android_elf_patch_rollback_command(args: argparse.Namespace) -> int:
    """Restore a patched Android ELF to a separate output copy."""

    try:
        from .tools import binary_patch_rollback_plan
    except ImportError:
        from reverse_analyzer.tools import binary_patch_rollback_plan

    rollback_path = Path(args.rollback_plan).expanduser().resolve()
    artifact_dir = Path(args.artifact_dir).expanduser().resolve() if args.artifact_dir else rollback_path.parent
    preflight = binary_patch_rollback_plan(
        args.patched,
        rollback=rollback_path,
        out_path=args.out,
        apply=False,
        artifact_dir=artifact_dir,
    )
    return _run_patch_capability(
        sample=args.patched,
        action="rollback",
        out_dir=artifact_dir,
        params={
            "rollback": str(rollback_path),
            "out_path": str(Path(args.out).expanduser().resolve()),
            "artifact_dir": str(artifact_dir),
        },
        compatibility_payload=_legacy_result_payload(preflight),
        refresh_patch_data=True,
        entrypoint="cli.patch.android-elf-rollback",
    )


def dll_proxy_command(args: argparse.Namespace) -> int:
    """Generate a forwarding-DLL project inside an explicit copy root."""

    try:
        from .tools import dll_proxy_generate
    except ImportError:
        from reverse_analyzer.tools import dll_proxy_generate

    result = dll_proxy_generate(
        args.sample,
        copy_dir=args.copy_dir,
        project_dir=args.project_dir,
        expected_architecture=args.architecture,
        proxy_name=args.proxy_name,
    )
    payload = _legacy_result_payload(result)
    _print_json_payload(payload)
    return 0 if getattr(result, "status", "failed") == "ok" else 2


def _load_cli_json(
    value: str | None,
    *,
    label: str,
    default: Any,
    allow_text: bool = False,
) -> Any:
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    if text.startswith(("[", "{")):
        return json.loads(text)
    path = Path(text).expanduser()
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8-sig"))
    if allow_text:
        return text
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} must be inline JSON or a readable JSON file") from exc


def gui_world_projection_command(args: argparse.Namespace) -> int:
    """Project explicit world geometry into a viewport evidence artifact."""

    try:
        from .tools import gui_world_projection
    except ImportError:
        from reverse_analyzer.tools import gui_world_projection

    try:
        matrix = _load_cli_json(args.matrix, label="matrix", default=[])
        viewport = _load_cli_json(args.viewport, label="viewport", default={})
        points = _load_cli_json(args.points, label="points", default=[])
        aabbs = _load_cli_json(args.aabbs, label="aabbs", default=[])
        matrix_source = _load_cli_json(
            args.matrix_source,
            label="matrix source",
            default="explicit-cli-input",
            allow_text=True,
        ) if args.matrix_source else "explicit-cli-input"
        coordinate_system = _load_cli_json(
            args.coordinate_system,
            label="coordinate system",
            default="world",
            allow_text=True,
        ) if args.coordinate_system else "world"
        metadata = _load_cli_json(args.metadata, label="metadata", default={}) if args.metadata else None
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        _print_json_payload(
            {
                "tool": "gui_world_projection",
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "data": {"status": "failed", "artifacts": []},
            }
        )
        return 2

    result = gui_world_projection(
        matrix=matrix,
        viewport=viewport,
        out_dir=args.out,
        points=points,
        aabbs=aabbs,
        matrix_layout=args.matrix_layout,
        clip_convention=args.clip_convention,
        handedness=args.handedness,
        reversed_z=bool(args.reversed_z),
        matrix_source=matrix_source,
        coordinate_system=coordinate_system,
        metadata=metadata,
    )
    payload = _legacy_result_payload(result)
    _print_json_payload(payload)
    return 0 if getattr(result, "status", "failed") == "ok" else 2


def evidence_verify_command(args: argparse.Namespace) -> int:
    """Verify a portable evidence manifest without executing a sample."""

    try:
        from .evidence import verify_manifest
    except ImportError:
        from reverse_analyzer.evidence import verify_manifest

    payload = verify_manifest(args.manifest)
    _print_json_payload(payload)
    return 0 if payload.get("status") == "ok" else 2


def environment_validate_command(args: argparse.Namespace) -> int:
    """Discover optional adapters and optionally execute bounded probes."""

    if validate_external_environment is None or write_environment_report is None:
        print("Environment validation runtime is unavailable.", file=sys.stderr)
        return 3
    try:
        overrides = _parse_capability_params(args.set)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report = validate_external_environment(
        overrides=overrides,
        execute_probes=bool(args.execute_probes),
        timeout=float(args.timeout),
    )
    acceptance_workspace = getattr(args, "acceptance_workspace", None)
    if acceptance_workspace and load_acceptance_records is not None and merge_acceptance_records is not None:
        report = merge_acceptance_records(report, load_acceptance_records(acceptance_workspace))
    artifact_path = write_environment_report(report, args.out) if args.out else None
    required = [str(item) for item in (args.require or [])]
    workflows = report.get("workflows") if isinstance(report, Mapping) else {}
    unmet = [
        name
        for name in required
        if not isinstance(workflows, Mapping)
        or not isinstance(workflows.get(name), Mapping)
        or not bool(workflows[name].get("verified"))
    ]
    if args.json or artifact_path is None:
        payload = dict(report)
        if artifact_path is not None:
            payload["artifact_path"] = str(artifact_path)
        if unmet:
            payload["unmet_requirements"] = unmet
        _print_json_payload(payload)
    else:
        summary = report.get("summary") if isinstance(report, Mapping) else {}
        print(
            "Environment validation: "
            f"verified={summary.get('verified', 0)} "
            f"dependency_gated={summary.get('dependency_gated', 0)} "
            f"unavailable={summary.get('unavailable', 0)}"
        )
        print(f"Artifact: {artifact_path}")
        if unmet:
            print(f"Unmet required workflows: {', '.join(unmet)}", file=sys.stderr)
    return 4 if unmet else 0


def environment_accept_list_command(args: argparse.Namespace) -> int:
    """List registered fixture readiness and any retained record history."""

    if list_acceptance_fixtures is None:
        print("Acceptance runtime is unavailable.", file=sys.stderr)
        return 3
    fixtures = list_acceptance_fixtures()
    records = load_acceptance_records(args.workspace) if load_acceptance_records is not None else []
    _print_json_payload(
        {
            "schema_version": 1,
            "workspace": str(Path(args.workspace).expanduser().resolve()),
            "fixtures": fixtures,
            "records": records,
        }
    )
    return 0


def environment_accept_run_command(args: argparse.Namespace) -> int:
    """Execute one immutable registered fixture and retain its proof record."""

    if run_acceptance_fixture is None:
        print("Acceptance runtime is unavailable.", file=sys.stderr)
        return 3
    target_identity: Mapping[str, Any] | None = None
    if args.target_identity:
        try:
            parsed = _load_cli_json(args.target_identity, label="target identity", default={})
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if not isinstance(parsed, Mapping):
            print("target identity must be a JSON object", file=sys.stderr)
            return 2
        target_identity = parsed
    try:
        record = run_acceptance_fixture(
            args.fixture,
            args.workspace,
            execute=bool(args.execute),
            timeout=float(args.timeout),
            target_identity=target_identity,
        )
    except (AcceptanceError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _print_json_payload(record)
    outcome = str(record.get("outcome") or "failed")
    if outcome == "passed":
        return 0
    if outcome == "dependency_gated":
        return 4
    if outcome == "unsupported_host":
        return 5
    return 2


def environment_accept_verify_command(args: argparse.Namespace) -> int:
    """Recompute hashes for one retained acceptance record."""

    if verify_acceptance_record is None:
        print("Acceptance runtime is unavailable.", file=sys.stderr)
        return 3
    payload = verify_acceptance_record(args.record)
    _print_json_payload(payload)
    return 0 if payload.get("status") == "ok" else 2


_KNOWN_DYNAMIC_PROFILES = {"quick", "behavior", "unpacking", "network", "persistence"}
_MAX_GUI_INTERACTION_TRACE_BYTES = 1024 * 1024
_CAPABILITY_REPORT_SECTIONS = {
    "anti_tamper_lab": "evidence_integrity",
    "memory_runtime": "memory_analysis",
    "dma_memory": "memory_analysis",
    "kernel_driver_memory_runtime": "memory_analysis",
    "native_debugger": "memory_analysis",
    "injector": "memory_analysis",
    "hook_runtime": "memory_analysis",
    "hook_target_resolver": "memory_analysis",
    "native_hook": "memory_analysis",
    "hardware_identity_virtualization": "memory_analysis",
    "patch_executor": "patch_analysis",
    "android_rebuild": "android_analysis",
    "android_native_patch": "android_analysis",
    "android_instrumentation": "android_analysis",
    "ios_rebuild": "ios_analysis",
    "ios_instrumentation": "ios_analysis",
    "engine_runtime": "engine_analysis",
    "protocol_runtime": "protocol_analysis",
    "graphics_present_runtime": "gui_analysis",
    "imgui_renderer_runtime": "gui_analysis",
    "render_overlay_runtime": "gui_analysis",
    "target_control_simulation": "gui_analysis",
    "llm_jailbreak": "llm_jailbreak_analysis",
}


def _normalize_dynamic_profile_hint(value: Any) -> Optional[str]:
    profile = str(value or "").lower()
    return profile if profile in _KNOWN_DYNAMIC_PROFILES else None


def _knowledge_dynamic_profile_hint(config: AnalyzerConfig) -> Optional[str]:
    if KnowledgeBase is None:
        return None
    try:
        recommendation = KnowledgeBase(config.knowledge_dir).recommend_dynamic_profile()
    except Exception:
        return None
    if not isinstance(recommendation, Mapping):
        return None
    return _normalize_dynamic_profile_hint(recommendation.get("profile"))


def _knowledge_gui_strategy_hint(config: AnalyzerConfig, framework: Optional[str] = None) -> Dict[str, Any]:
    if KnowledgeBase is None:
        return {}
    try:
        recommendation = KnowledgeBase(config.knowledge_dir).recommend_gui_strategy(framework=framework)
    except Exception:
        return {}
    return recommendation if isinstance(recommendation, dict) else {}


def _resolve_dynamic_profile(
    requested: str,
    tool_results: Sequence[Mapping[str, Any]],
    historical_profile: Optional[str] = None,
) -> str:
    """Choose a Frida hook profile from static observations when requested."""

    requested_profile = str(requested or "auto").lower()
    if requested_profile != "auto":
        return requested_profile

    history_profile = _normalize_dynamic_profile_hint(historical_profile)
    static_text = " ".join(_static_signal_tokens(tool_results)).lower()
    if not static_text.strip():
        return history_profile or "quick"
    packer_score = _max_numeric_signal(tool_results, "score")
    shell_score = _max_numeric_signal(tool_results, "shell_score")
    if (
        "packed_likely:true" in static_text
        or packer_score >= 50
        or shell_score >= 40
        or any(token in static_text for token in ("upx0", "upx1", "virtualalloc", "virtualprotect", "getprocaddress", "loadlibrary", "createremotethread", "ntqueryinformationprocess"))
    ):
        return "unpacking"
    if any(token in static_text for token in ("winhttp", "wininet", "internetconnect", "httpsendrequest", "urldownloadtofile", "ws2_32", "socket", "connect", "recv", "send", "http://", "https://", "/api/")):
        return "network"
    if any(token in static_text for token in ("regcreate", "regset", "run key", "\\run", "createfile", "writefile", "appdata", "startup")):
        return "persistence"
    return history_profile or "quick"


def _static_signal_tokens(tool_results: Sequence[Mapping[str, Any]]) -> list[str]:
    tokens: list[str] = []
    for trace in tool_results:
        payload = _trace_payload(trace)
        if not isinstance(payload, Mapping):
            continue
        tool_name = _trace_tool_name(trace)
        if tool_name == "packer_detect":
            tokens.append(f"packed_likely:{str(bool(payload.get('packed_likely'))).lower()}")
        _collect_static_tokens(payload, tokens, depth=0)
    return tokens[:5000]


def _collect_static_tokens(value: Any, tokens: list[str], *, depth: int) -> None:
    if depth > 4 or len(tokens) > 5000:
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in {"strings", "name", "dll", "library", "module", "section", "value", "label", "symbol", "shell_verdict"}:
                tokens.append(str(item))
            elif key in {"packed_likely", "score", "shell_score"}:
                tokens.append(f"{key}:{item}")
            _collect_static_tokens(item, tokens, depth=depth + 1)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in list(value)[:200]:
            _collect_static_tokens(item, tokens, depth=depth + 1)
    elif isinstance(value, (str, bytes)):
        text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
        if len(text) <= 200:
            tokens.append(text)


def _max_numeric_signal(tool_results: Sequence[Mapping[str, Any]], key: str) -> float:
    values: list[float] = []
    for trace in tool_results:
        payload = _trace_payload(trace)
        if isinstance(payload, Mapping):
            _collect_numeric_signal(payload, key, values, depth=0)
    return max(values) if values else 0.0


def _collect_numeric_signal(value: Any, key: str, values: list[float], *, depth: int) -> None:
    if depth > 4:
        return
    if isinstance(value, Mapping):
        if key in value:
            try:
                values.append(float(value[key]))
            except (TypeError, ValueError):
                pass
        for item in value.values():
            _collect_numeric_signal(item, key, values, depth=depth + 1)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in list(value)[:200]:
            _collect_numeric_signal(item, key, values, depth=depth + 1)


def _new_session(sample: Path, out_dir: Path, max_iterations: int) -> Any:
    try:
        from .core.models import Flow, ReverseSession, Task
    except Exception as exc:
        raise RuntimeError(f"ReverseSession models are not importable: {exc}") from exc

    session = ReverseSession(
        target=str(sample),
        metadata={"out_dir": str(out_dir), "max_iterations": max_iterations, "migration": "pe"},
    )
    flow = Flow("binary-analysis", "PE-style reverse-analysis flow")
    flow.add_task(Task("identify", "Identify sample format, metadata, and entry points"))
    flow.add_task(Task("analyze", "Run tool-assisted static analysis and collect findings"))
    flow.add_task(Task("report", "Build human-readable and machine-readable reports"))
    session.add_flow(flow)
    return session


def analyze_command(args: argparse.Namespace) -> int:
    config = load_config()
    ensure_runtime_dirs(config)
    sample = Path(args.sample).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not sample.exists():
        print(f"error: sample does not exist: {sample}", file=sys.stderr)
        return 2

    session = _new_session(sample, out_dir, args.max_iterations)
    missing: list[str] = []
    loaded: dict[str, Any] = {}
    for symbol in ("ToolExecutor", "ReportBuilder", "AgentLoop"):
        try:
            loaded[symbol] = _load_symbol(symbol)
        except RuntimeError as exc:
            missing.append(str(exc))
    if missing:
        print("error: analysis runtime is incomplete; PE orchestration modules are not ready.", file=sys.stderr)
        for item in missing:
            print(f"- {item}", file=sys.stderr)
        print(f"session initialized: {session.session_id}", file=sys.stderr)
        return 3

    trace_logger = TraceLogger(out_dir / "trace.jsonl") if TraceLogger is not None else None
    session_store = SessionStore(out_dir, trace_logger=trace_logger) if SessionStore is not None else None
    if session_store is not None:
        session_store.save(session)

    tool_executor = _instantiate(loaded["ToolExecutor"], config=config, out_dir=out_dir)
    if register_builtin_tools is not None:
        register_builtin_tools(tool_executor)

    provider_tool_args: dict[str, dict[str, Any]] = {}
    if args.yara_rules:
        provider_tool_args["yara_scan"] = {"rules_path": str(Path(args.yara_rules).resolve())}
    provider = RuleBasedProvider(tool_args=provider_tool_args) if RuleBasedProvider is not None else None

    agent_loop = _instantiate(
        loaded["AgentLoop"],
        provider=provider,
        session=session,
        tool_executor=tool_executor,
        config=config,
        max_iterations=args.max_iterations,
        trace=trace_logger,
    )
    try:
        result = _call_first(agent_loop, ("run", "execute", "analyze"), {"session": session, "max_iterations": args.max_iterations})
    except TypeError:
        result = _call_first(agent_loop, ("run", "execute", "analyze"))
    tool_results = getattr(result, "tool_results", None) or getattr(agent_loop, "tool_results", [])
    _mark_flow_task(
        session,
        session_store,
        flow_name="binary-analysis",
        task_name="identify",
        status="succeeded",
        result={"sample": str(sample), "out_dir": str(out_dir)},
        message="sample_identified",
    )
    _mark_flow_task(
        session,
        session_store,
        flow_name="binary-analysis",
        task_name="analyze",
        status="succeeded",
        result={"tool_count": len(tool_results), "tools": [item.get("tool_name") for item in tool_results]},
        message="analysis_completed",
    )

    extra_artifacts: list[str] = []
    if args.dynamic:
        dynamic_hooks = _load_dynamic_hooks(args.dynamic_hook_file) if args.dynamic_hook_file else None
        historical_dynamic_profile = _knowledge_dynamic_profile_hint(config)
        resolved_dynamic_profile = "custom" if dynamic_hooks is not None else _resolve_dynamic_profile(args.dynamic_profile, tool_results, historical_dynamic_profile)
        selected_backends = ("frida", "procmon") if args.dynamic_backend == "all" else (args.dynamic_backend,)
        for backend in selected_backends:
            if backend == "frida":
                dynamic_result = tool_executor.execute(
                    "frida_trace",
                    path=str(sample),
                    out_dir=str(out_dir),
                    duration=args.dynamic_duration,
                    target_args=args.dynamic_arg or [],
                    attach_pid=args.attach_pid,
                    hooks=dynamic_hooks,
                    hook_profile=resolved_dynamic_profile,
                )
                tool_name = "frida_trace"
                input_payload = {
                    "path": str(sample),
                    "out_dir": str(out_dir),
                    "duration": args.dynamic_duration,
                    "target_args": list(args.dynamic_arg or []),
                    "attach_pid": args.attach_pid,
                    "dynamic_hook_file": args.dynamic_hook_file,
                    "dynamic_profile": resolved_dynamic_profile,
                    "requested_dynamic_profile": args.dynamic_profile,
                    "historical_dynamic_profile": historical_dynamic_profile,
                }
                unavailable_message = "Frida dynamic tracing not configured. Run: python -m reverse_analyzer --install-guide frida"
            else:
                dynamic_result = tool_executor.execute(
                    "procmon_trace",
                    path=str(sample),
                    out_dir=str(out_dir),
                    duration=args.dynamic_duration,
                    target_args=args.dynamic_arg or [],
                    attach_pid=args.attach_pid,
                    procmon_path=args.procmon_path,
                )
                tool_name = "procmon_trace"
                input_payload = {
                    "path": str(sample),
                    "out_dir": str(out_dir),
                    "duration": args.dynamic_duration,
                    "target_args": list(args.dynamic_arg or []),
                    "attach_pid": args.attach_pid,
                    "procmon_path": args.procmon_path,
                }
                unavailable_message = "Procmon behavioral capture not configured. Run: python -m reverse_analyzer --install-guide procmon"

            _append_observation(
                tool_results,
                result,
                session,
                session_store,
                tool_name,
                input_payload,
                dynamic_result,
            )
            extra_artifacts.extend(_record_artifacts(session, session_store, dynamic_result))
            if _result_status(dynamic_result) == "unavailable":
                print(unavailable_message, file=sys.stderr)

    if args.decompile:
        ghidra_result = tool_executor.execute(
            "ghidra_decompile",
            path=str(sample),
            out_dir=str(out_dir),
            ghidra_home=args.ghidra_home,
            timeout=args.decompiler_timeout,
        )
        _append_observation(
            tool_results,
            result,
            session,
            session_store,
            "ghidra_decompile",
            {
                "path": str(sample),
                "out_dir": str(out_dir),
                "ghidra_home": args.ghidra_home,
                "timeout": args.decompiler_timeout,
            },
            ghidra_result,
        )
        extra_artifacts.extend(_record_artifacts(session, session_store, ghidra_result))
        if _result_status(ghidra_result) == "unavailable":
            print("Ghidra Headless not configured. Run: python -m reverse_analyzer --install-guide ghidra", file=sys.stderr)

    if getattr(args, "memory_analysis", False) or getattr(args, "memory_plan", None):
        extra_artifacts.extend(
            _run_memory_analysis(
                tool_executor,
                tool_results,
                result,
                session,
                session_store,
                sample,
                out_dir,
                attach_pid=getattr(args, "attach_pid", None),
                plan_path=getattr(args, "memory_plan", None),
            )
        )

    if args.gui or args.reconstruct_gui or getattr(args, "gui_interaction_trace", None):
        extra_artifacts.extend(
            _run_gui_pipeline(
                tool_executor,
                tool_results,
                result,
                session,
                session_store,
                sample,
                out_dir,
                args,
                config,
            )
        )

    post_stage_start = len(tool_results)
    extra_artifacts.extend(
        _run_engine_analysis(
            tool_executor,
            tool_results,
            result,
            session,
            session_store,
            sample,
            out_dir,
        )
    )
    extra_artifacts.extend(
        _run_android_analysis(
            tool_executor,
            tool_results,
            result,
            session,
            session_store,
            sample,
            out_dir,
        )
    )
    if sample.suffix.casefold() == ".ipa" or getattr(args, "require_ios", False):
        extra_artifacts.extend(
            _run_ios_analysis(
                tool_executor,
                tool_results,
                result,
                session,
                session_store,
                sample,
                out_dir,
            )
        )
    extra_artifacts.extend(
        _run_protocol_analysis(
            tool_executor,
            tool_results,
            result,
            session,
            session_store,
            sample,
            out_dir,
        )
    )

    extra_artifacts.extend(
        _run_behavior_graph(
            tool_executor,
            tool_results,
            result,
            session,
            session_store,
            out_dir,
        )
    )
    semantic_result, semantic_artifacts = _run_semantic_ir(
        tool_executor,
        tool_results,
        result,
        session,
        session_store,
        out_dir,
    )
    extra_artifacts.extend(semantic_artifacts)
    semantic_ir = _result_payload(semantic_result)
    if not isinstance(semantic_ir, Mapping):
        semantic_ir = {}

    if args.reconstruct_gui:
        extra_artifacts.extend(
            _run_gui_reconstruction(
                tool_executor,
                tool_results,
                result,
                session,
                session_store,
                sample,
                out_dir,
                semantic_ir,
            )
        )

    if args.reconstruct:
        analysis = _build_reconstruction_analysis(tool_results)
        if semantic_ir:
            analysis["semantic_ir"] = dict(semantic_ir)
        reconstruct_result = tool_executor.execute(
            "reconstruct_project",
            path=str(sample),
            out_dir=str(out_dir),
            analysis=analysis,
            validate=True,
            validation_options={},
            runtime_validation_spec=getattr(args, "runtime_validation_spec", None),
            behavior_validation_spec=getattr(args, "behavior_validation_spec", None),
            behavior_original_dir=getattr(args, "behavior_original_dir", None),
        )
        _append_observation(
            tool_results,
            result,
            session,
            session_store,
            "reconstruct_project",
            {
                "path": str(sample),
                "out_dir": str(out_dir),
                "analysis": analysis,
                "runtime_validation_spec": getattr(args, "runtime_validation_spec", None),
                "behavior_validation_spec": getattr(args, "behavior_validation_spec", None),
                "behavior_original_dir": getattr(args, "behavior_original_dir", None),
            },
            reconstruct_result,
        )
        extra_artifacts.extend(_record_artifacts(session, session_store, reconstruct_result))
        _register_reconstruction_runtime(session, session_store, reconstruct_result)
        reconstruction_payload = _result_payload(reconstruct_result)
        project_dir = reconstruction_payload.get("project_dir") if isinstance(reconstruction_payload, Mapping) else None
        if project_dir:
            verification_result = tool_executor.execute(
                "reconstruction_verify",
                project_dir=str(project_dir),
                semantic_ir=semantic_ir,
            )
            _append_observation(
                tool_results,
                result,
                session,
                session_store,
                "reconstruction_verify",
                {"project_dir": str(project_dir), "semantic_ir": semantic_ir},
                verification_result,
            )
            extra_artifacts.extend(_record_artifacts(session, session_store, verification_result))

    required_post_tools: set[str] = set()
    if args.reconstruct_gui:
        required_post_tools.update({"reconstruct_gui_project", "reconstruction_verify"})
    if args.reconstruct:
        required_post_tools.update({"reconstruct_project", "reconstruction_verify"})
    if getattr(args, "require_ios", False):
        required_post_tools.add("ios_analyze")
    analysis_outcome = _aggregate_stage_outcome(
        tool_results[post_stage_start:],
        required_tools=required_post_tools,
        optional_tools={"engine_analyze", "android_analyze", "ios_analyze", "protocol_analyze"},
    )
    _ensure_session_metadata(session)["analysis_outcome"] = dict(analysis_outcome)
    _mark_flow_task(
        session,
        session_store,
        flow_name="binary-analysis",
        task_name="analyze",
        status="failed" if analysis_outcome["hard_failure"] else "succeeded",
        result={
            "tool_count": len(tool_results),
            "tools": [item.get("tool_name") for item in tool_results if isinstance(item, Mapping)],
            "analysis_outcome": analysis_outcome,
        },
        error=_stage_outcome_error(analysis_outcome),
        message="analysis_failed" if analysis_outcome["hard_failure"] else "analysis_completed",
    )

    if session_store is not None:
        session_store.save(session)

    evidence_manifest = _write_evidence_manifest(
        session,
        session_store,
        sample,
        out_dir,
        tool_results,
    )
    if evidence_manifest is not None:
        extra_artifacts.append(str(evidence_manifest))
    if session_store is not None:
        session_store.save(session)

    report_builder = _instantiate(loaded["ReportBuilder"], session, tool_results, {}, config=config, out_dir=out_dir)
    report_data = _call_first(report_builder, ("build", "render"))
    _finalize_platform_core_artifacts(
        report_data,
        out_dir,
        sample_path=str(sample) if sample else None,
    )
    refreshed_manifest = _write_evidence_manifest(
        session,
        session_store,
        sample,
        out_dir,
        tool_results,
    )
    if refreshed_manifest is not None and str(refreshed_manifest) not in extra_artifacts:
        extra_artifacts.append(str(refreshed_manifest))
    report_data["evidence_integrity"] = _session_evidence_integrity(session)
    report_data["analysis_outcome"] = dict(analysis_outcome)
    _persist_knowledge(config, sample, session, out_dir, report_data, tool_results)

    report_json = out_dir / "report.json"
    report_md = out_dir / "report.md"
    report_json.write_text(json.dumps(report_data, default=str, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if hasattr(report_builder, "to_markdown"):
        report_md.write_text(report_builder.to_markdown(), encoding="utf-8")

    _mark_flow_task(
        session,
        session_store,
        flow_name="binary-analysis",
        task_name="report",
        status="succeeded",
        result={"report_json": str(report_json), "report_md": str(report_md)},
        message="report_generated",
    )
    _finalize_session_status(session, session_store, stopped_reason=getattr(result, "stopped_reason", ""))

    session.artifacts.extend(
        [
            {"name": "report.json", "path": str(report_json), "kind": "report"},
            {"name": "report.md", "path": str(report_md), "kind": "report"},
        ]
    )
    if session_store is not None:
        session_store.save(session)

    print(
        json.dumps(
            {
                "session_id": session.session_id,
                "out_dir": str(out_dir),
                "status": analysis_outcome["status"],
                "analysis_outcome": analysis_outcome,
                "result": result.to_dict() if hasattr(result, "to_dict") else result,
                "artifacts": [str(report_json), str(report_md), *extra_artifacts],
            },
            default=str,
            ensure_ascii=False,
            indent=2,
        )
    )
    return 2 if analysis_outcome["hard_failure"] else 0



def _finalize_platform_core_artifacts(report_data, out_dir, sample_path=None):
    if finalize_platform_core is None or build_default_registry is None:
        return {}
    registry = build_default_registry()
    return finalize_platform_core(
        report_data,
        out_dir=str(out_dir),
        sample_path=sample_path,
        registry=registry,
    )

def init_knowledge_command(args: argparse.Namespace) -> int:
    config = load_config(args.workspace)
    manifest = write_default_knowledge(config)
    if KnowledgeBase is not None:
        try:
            KnowledgeBase(config.knowledge_dir)
        except Exception:
            pass
    print(f"Knowledge initialized: {manifest}")
    return 0


def show_knowledge_command(args: argparse.Namespace) -> int:
    config = load_config(args.workspace)
    manifest = write_default_knowledge(config) if args.init_if_missing else config.knowledge_dir / "knowledge.json"
    if not manifest.exists():
        print(f"Knowledge manifest not found: {manifest}", file=sys.stderr)
        print("Run: python -m reverse_analyzer init-knowledge", file=sys.stderr)
        return 2
    print(manifest.read_text(encoding="utf-8"))
    return 0


def list_tools_command(args: argparse.Namespace) -> int:
    tools = list(_BUILTIN_TOOLS)
    for symbol, modules in _RUNTIME_IMPORTS.items():
        try:
            _load_symbol(symbol)
            status = "available"
        except RuntimeError:
            status = "not-yet-implemented"
        tools.append({"name": symbol, "status": status, "modules": list(modules)})
    ghidra_entry = {
        "name": "ghidra",
        "description": "Optional Ghidra Headless decompiler backend with install guide support.",
        "commands": ["--install-guide ghidra", "analyze --decompile", "analyze --ghidra-home <path>"],
    }
    frida_entry = {
        "name": "frida",
        "description": "Optional Frida dynamic tracing backend with install guide support.",
        "commands": [
            "--install-guide frida",
            "analyze --dynamic",
            "analyze --dynamic --dynamic-duration 15",
            "analyze --dynamic --dynamic-profile auto",
            "analyze --dynamic --dynamic-profile unpacking",
            "analyze --dynamic --dynamic-profile network",
            "analyze --dynamic --dynamic-hook-file hooks.json",
        ],
    }
    procmon_entry = {
        "name": "procmon",
        "description": "Optional Microsoft Sysinternals Procmon backend for OS-level behavioral capture.",
        "commands": [
            "--install-guide procmon",
            "analyze --dynamic --dynamic-backend procmon",
            "analyze --dynamic --dynamic-backend all",
            "analyze --dynamic --dynamic-backend procmon --procmon-path C:\\Tools\\Procmon64.exe",
        ],
    }
    try:
        from reverse_analyzer.tools import ghidra_check as _ghidra_check

        check = _ghidra_check()
        ghidra_entry["status"] = check.get("status", "unknown")
        if check.get("headless_path"):
            ghidra_entry["headless_path"] = check["headless_path"]
        if check.get("setup_hint"):
            ghidra_entry["setup_hint"] = check["setup_hint"]
    except Exception as exc:
        ghidra_entry["status"] = "unavailable"
        ghidra_entry["error"] = str(exc)
    try:
        from reverse_analyzer.tools import frida_check as _frida_check

        check = _frida_check()
        frida_entry["status"] = check.get("status", "unknown")
        if check.get("cli_path"):
            frida_entry["cli_path"] = check["cli_path"]
        if check.get("setup_hint"):
            frida_entry["setup_hint"] = check["setup_hint"]
        if check.get("version"):
            frida_entry["version"] = check["version"]
    except Exception as exc:
        frida_entry["status"] = "unavailable"
        frida_entry["error"] = str(exc)
    try:
        from reverse_analyzer.tools import procmon_check as _procmon_check

        check = _procmon_check()
        procmon_entry["status"] = check.get("status", "unknown")
        if check.get("path"):
            procmon_entry["path"] = check["path"]
        if check.get("setup_hint"):
            procmon_entry["setup_hint"] = check["setup_hint"]
    except Exception as exc:
        procmon_entry["status"] = "unavailable"
        procmon_entry["error"] = str(exc)
    tools.append(ghidra_entry)
    tools.append(frida_entry)
    tools.append(procmon_entry)
    if args.json:
        print(json.dumps(tools, indent=2, ensure_ascii=False))
    else:
        for tool in tools:
            print(f"{tool['name']}: {tool['status']}")
            if "description" in tool:
                print(f"  {tool['description']}")
            if tool.get("headless_path"):
                print(f"  headless: {tool['headless_path']}")
            if tool.get("setup_hint"):
                print(f"  setup: {tool['setup_hint']}")
    return 0


def _capability_section_name(capability_name: str) -> str:
    return _CAPABILITY_REPORT_SECTIONS.get(str(capability_name or "").lower(), "capability_analysis")


def _capability_precondition_hash(request: Any) -> str:
    target = getattr(request, "target", None)
    target_hash = getattr(target, "sha256", None)
    if target_hash:
        return str(target_hash)
    payload = {
        "capability": getattr(request, "capability", None),
        "action": getattr(request, "action", None),
        "session_id": getattr(request, "session_id", None),
        "target": target.to_dict() if hasattr(target, "to_dict") else dict(target or {}),
        "params": dict(getattr(request, "params", {}) or {}),
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _capability_synthetic_failure(
    request: Any,
    *,
    provider_name: str,
    phase: str,
    reason: str,
    status: str = "failed",
    plan: Any = None,
    validation: Any = None,
    prior_result: Any = None,
) -> tuple[Any, Any, Any, Any]:
    if any(
        model is None
        for model in (
            CapabilityArtifact,
            CapabilityArtifactBundle,
            CapabilityExecutionResult,
            CapabilityPlan,
            CapabilityValidation,
        )
    ):
        raise RuntimeError("Capability result models are unavailable")

    precondition_hash = (
        getattr(plan, "precondition_hash", None) if plan is not None else None
    ) or _capability_precondition_hash(request)
    before_snapshot = dict(getattr(prior_result, "before_snapshot", {}) or {}) if prior_result is not None else {}
    if not before_snapshot and plan is not None:
        before_snapshot = dict(getattr(plan, "before_snapshot", {}) or {})
    if not before_snapshot:
        before_snapshot = {
            "status": "not_captured",
            "phase": phase,
            "reason": reason,
        }
    rollback_plan = dict(getattr(prior_result, "rollback_plan", {}) or {}) if prior_result is not None else {}
    if not rollback_plan and plan is not None:
        rollback_plan = dict(getattr(plan, "rollback_plan", {}) or {})
    if not rollback_plan:
        rollback_plan = {
            "supported": False,
            "status": "not_required",
            "reason": "execution did not complete",
        }
    if plan is None:
        plan = CapabilityPlan(
            capability=str(request.capability),
            provider=provider_name,
            session_id=str(request.session_id),
            target=request.target,
            action=str(request.action),
            parameters=dict(request.params or {}),
            steps=[{"phase": phase, "status": "failed", "reason": reason}],
            precondition_hash=precondition_hash,
            before_snapshot=before_snapshot,
            rollback_plan=rollback_plan,
            provenance=dict(request.provenance or {}),
        )
    if validation is None:
        validation = CapabilityValidation(
            capability=str(request.capability),
            provider=provider_name,
            session_id=str(request.session_id),
            ok=False,
            checks=[{"name": phase, "status": "failed", "reason": reason}],
            errors=[reason],
        )

    safe_capability = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(request.capability))
    safe_action = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(request.action))
    artifact_path = f"capabilities/{safe_capability}_{safe_action}_{phase}_{status}.json"
    artifact = CapabilityArtifact(
        path=artifact_path,
        kind="json",
        description="Structured capability failure evidence",
        metadata={"phase": phase, "reason": reason},
    )
    report_section = {
        "capability": str(request.capability),
        "provider": provider_name,
        "action": str(request.action),
        "status": status,
        "phase": phase,
        "reason": reason,
    }
    dashboard_trace = [
        {
            "kind": "capability_execution",
            "capability": str(request.capability),
            "provider": provider_name,
            "action": str(request.action),
            "status": status,
            "phase": phase,
            "reason": reason,
        }
    ]
    provenance = dict(request.provenance or {})
    provenance.update(
        {
            "precondition_hash": precondition_hash,
            "plan": plan.to_dict() if hasattr(plan, "to_dict") else dict(plan or {}),
            "validation": (
                validation.to_dict() if hasattr(validation, "to_dict") else dict(validation or {})
            ),
            "failure": {"phase": phase, "reason": reason, "status": status},
        }
    )
    if prior_result is not None:
        provenance["prior_result"] = (
            prior_result.to_dict() if hasattr(prior_result, "to_dict") else dict(prior_result or {})
        )
    after_snapshot = dict(getattr(prior_result, "after_snapshot", {}) or {}) if prior_result is not None else {}
    if not after_snapshot:
        after_snapshot = {"status": "not_executed", "phase": phase, "reason": reason}
    result = CapabilityExecutionResult(
        capability=str(request.capability),
        provider=provider_name,
        session_id=str(request.session_id),
        status=status,
        action=str(request.action),
        target=request.target,
        before_snapshot=before_snapshot,
        after_snapshot=after_snapshot,
        rollback_plan=rollback_plan,
        artifacts=[artifact],
        evidence_manifest_entries=[{"path": artifact_path, "kind": "json", "role": "failure_evidence"}],
        report_section=report_section,
        dashboard_trace=dashboard_trace,
        provenance=provenance,
    )
    bundle = CapabilityArtifactBundle(
        capability=str(request.capability),
        provider=provider_name,
        session_id=str(request.session_id),
        artifacts=[artifact],
        manifest_entries=list(result.evidence_manifest_entries),
    )
    return plan, validation, result, bundle


def _capability_result_outcome(result: Any, rollback_result: Any = None) -> tuple[str, int]:
    if rollback_result is not None:
        rollback_ok = (
            rollback_result.get("ok")
            if isinstance(rollback_result, Mapping)
            else getattr(rollback_result, "ok", False)
        )
        if not bool(rollback_ok):
            return "failed", 2
    raw_status = getattr(result, "status", None)
    if raw_status is None and isinstance(result, Mapping):
        raw_status = result.get("status")
    status = str(raw_status or "unknown").strip().lower().replace("-", "_")
    if status in {
        "ok",
        "success",
        "succeeded",
        "complete",
        "completed",
        "executed",
        "planned",
        "validated",
        "verified",
        "applied",
        "restored",
        "rebuilt",
        "rolled_back",
    }:
        return "succeeded", 0
    if status in {"mock", "mocked", "dry_run", "simulated"}:
        return "skipped", 0
    if status in {
        "unavailable",
        "unsupported",
        "not_supported",
        "not_available",
        "not_run",
        "skipped",
    }:
        return "skipped", 3
    return "failed", 2


def _required_jailbreak_success_missing(args: argparse.Namespace, result: Any) -> bool:
    """Return whether the CLI explicitly required a confirmed jailbreak success."""

    if not bool(getattr(args, "require_success", False)):
        return False
    if str(getattr(args, "capability", "") or "").strip().lower() != "llm_jailbreak":
        return False
    result_payload = result.to_dict() if hasattr(result, "to_dict") else dict(result or {})
    report_section = (
        result_payload.get("report_section")
        if isinstance(result_payload.get("report_section"), Mapping)
        else {}
    )
    return report_section.get("success") is not True


def _capability_failure_phase(result: Any) -> str | None:
    provenance = getattr(result, "provenance", None)
    if provenance is None and isinstance(result, Mapping):
        provenance = result.get("provenance")
    failure = provenance.get("failure") if isinstance(provenance, Mapping) else None
    if not isinstance(failure, Mapping):
        return None
    phase = str(failure.get("phase") or "").strip()
    return phase or None


def _capability_section_payload(
    *,
    capability_name: str,
    action: str,
    target: Any,
    provider: Any,
    validation: Any,
    result: Any,
    rollback_result: Any,
    artifact_paths: Sequence[str],
) -> dict[str, Any]:
    target_payload = target.to_dict() if hasattr(target, "to_dict") else dict(target or {})
    validation_payload = validation.to_dict() if hasattr(validation, "to_dict") else dict(validation or {})
    result_payload = result.to_dict() if hasattr(result, "to_dict") else dict(result or {})
    rollback_payload = (
        rollback_result.to_dict()
        if rollback_result is not None and hasattr(rollback_result, "to_dict")
        else (dict(rollback_result or {}) if rollback_result is not None else None)
    )
    report_section = result_payload.get("report_section") if isinstance(result_payload, Mapping) else {}
    if not isinstance(report_section, Mapping):
        report_section = {}
    artifacts = [dict(item) for item in (result_payload.get("artifacts") or []) if isinstance(item, Mapping)]
    dashboard_trace = [dict(item) for item in (result_payload.get("dashboard_trace") or []) if isinstance(item, Mapping)]
    payload = {
        "status": result_payload.get("status") or "unknown",
        "capability": capability_name,
        "action": action,
        "provider": result_payload.get("provider") or getattr(provider, "provider_name", None),
        "session_id": result_payload.get("session_id"),
        "target": target_payload,
        "validation": validation_payload,
        "before_snapshot": dict(result_payload.get("before_snapshot") or {}),
        "after_snapshot": dict(result_payload.get("after_snapshot") or {}),
        "rollback_plan": dict(result_payload.get("rollback_plan") or {}),
        "rollback": rollback_payload,
        "artifacts": artifacts,
        "artifact_count": len(artifact_paths),
        "artifact_paths": [str(item) for item in artifact_paths],
        "dashboard_trace": dashboard_trace,
        "report_section": dict(report_section),
    }
    merged = dict(report_section)
    merged.update(payload)
    return merged


def _capability_markdown_section(capability_name: str, section: Mapping[str, Any]) -> str:
    heading = "Model Jailbreak" if capability_name == "llm_jailbreak" else "Capability Execution"
    lines = ["", f"## {heading}", ""]
    lines.append(f"- **Capability:** {capability_name}")
    lines.append(f"- **Action:** {section.get('action') or 'unknown'}")
    lines.append(f"- **Status:** {section.get('status') or 'unknown'}")
    lines.append(f"- **Provider:** {section.get('provider') or 'unknown'}")
    if section.get("session_id"):
        lines.append(f"- **Session ID:** {section['session_id']}")
    validation = section.get("validation") if isinstance(section.get("validation"), Mapping) else {}
    if validation:
        lines.append(f"- **Validation OK:** {validation.get('ok')}")
        checks = validation.get("checks") if isinstance(validation.get("checks"), Sequence) else []
        if checks and not isinstance(checks, (str, bytes, bytearray)):
            lines.append(f"- **Validation Checks:** {len(checks)}")
        warnings = validation.get("warnings") if isinstance(validation.get("warnings"), Sequence) else []
        if warnings and not isinstance(warnings, (str, bytes, bytearray)):
            lines.append(f"- **Warnings:** {len(warnings)}")
        errors = validation.get("errors") if isinstance(validation.get("errors"), Sequence) else []
        if errors and not isinstance(errors, (str, bytes, bytearray)):
            lines.append(f"- **Errors:** {len(errors)}")
    target = section.get("target") if isinstance(section.get("target"), Mapping) else {}
    if target:
        target_label = target.get("display_name") or target.get("path") or target.get("pid") or target.get("kind")
        if target_label:
            lines.append(f"- **Target:** {target_label}")
    if section.get("artifact_count") is not None:
        lines.append(f"- **Artifacts:** {section.get('artifact_count', 0)}")
    if capability_name == "llm_jailbreak":
        for label, key in (
            ("Model", "model"),
            ("Campaign", "campaign_id"),
            ("Strategy", "strategy"),
            ("Attempts", "attempt_count"),
            ("Success", "success"),
            ("Score", "score"),
            ("Latency (ms)", "latency_ms"),
        ):
            if section.get(key) is not None:
                lines.append(f"- **{label}:** {section[key]}")
    rollback = section.get("rollback") if isinstance(section.get("rollback"), Mapping) else {}
    if rollback:
        lines.append(f"- **Rollback:** ok={rollback.get('ok')} restored={rollback.get('restored')}")
    return "\n".join(lines) + "\n"


def list_capabilities_command(args: argparse.Namespace) -> int:
    if build_default_registry is None:
        print("Capability registry is unavailable because provider modules could not be imported.", file=sys.stderr)
        return 3
    registry = build_default_registry()
    payload = {
        "capabilities": [
            {
                "name": capability_name,
                "providers": registry.list_providers(capability_name),
            }
            for capability_name in registry.list_capabilities()
        ]
    }
    if args.json:
        _print_json_payload(payload)
    else:
        for item in payload["capabilities"]:
            providers = ", ".join(item["providers"]) if item["providers"] else "none"
            print(f"{item['name']}: {providers}")
    return 0


def show_capability_audit_command(args: argparse.Namespace) -> int:
    report_path = Path(args.report).resolve()
    if not report_path.exists():
        print(f"error: report does not exist: {report_path}", file=sys.stderr)
        return 2
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # noqa: BLE001 - CLI must stay machine-readable on malformed input
        print(f"error: could not read report: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    capability_audit = payload.get("capability_audit") if isinstance(payload, Mapping) else {}
    _print_json_payload(capability_audit if isinstance(capability_audit, Mapping) else {})
    return 0


def capability_run_command(args: argparse.Namespace) -> int:
    if CapabilityRequest is None or CapabilityAuditBuilder is None or build_default_registry is None:
        print("Capability execution runtime is unavailable because core modules could not be imported.", file=sys.stderr)
        return 3
    target_identity_override = getattr(args, "target_identity_override", None)
    if not args.sample and args.pid is None and target_identity_override is None:
        print("error: capability run requires --sample or --pid", file=sys.stderr)
        return 2

    config = load_config()
    ensure_runtime_dirs(config)
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    sample_path = Path(args.sample).resolve() if args.sample else None
    if sample_path is not None and not sample_path.exists():
        print(f"error: sample does not exist: {sample_path}", file=sys.stderr)
        return 2

    try:
        params = _parse_capability_params(args.param)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        target = target_identity_override or _capability_target_identity(
            str(sample_path) if sample_path is not None else None,
            args.pid,
        )
        session = _new_capability_session(target, out_dir, args.capability, args.action, args.provider)
    except Exception as exc:  # noqa: BLE001 - runtime bootstrap must fail clearly
        print(f"error: capability bootstrap failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3

    trace_logger = TraceLogger(out_dir / "trace.jsonl") if TraceLogger is not None else None
    session_store = SessionStore(out_dir, trace_logger=trace_logger) if SessionStore is not None else None
    if session_store is not None:
        session_store.save(session)

    tool_results: list[dict[str, Any]] = []
    request = CapabilityRequest(
        capability=args.capability,
        action=args.action,
        target=target,
        params=params,
        session_id=session.session_id,
        requested_provider=args.provider,
        provenance={
            "entrypoint": getattr(args, "entrypoint", "cli.capability.run"),
            "out_dir": str(out_dir),
            "sample_path": str(sample_path) if sample_path is not None else None,
            "pid": args.pid,
            "params": dict(params),
        },
    )
    registry = build_default_registry()
    audit_builder = CapabilityAuditBuilder()

    try:
        provider, plan, validation, execution_result, rollback_result, artifact_paths = _execute_capability_request(
            registry=registry,
            request=request,
            out_dir=out_dir,
            session=session,
            session_store=session_store,
            audit_builder=audit_builder,
            rollback=bool(args.rollback),
        )
    except LookupError as exc:
        _mark_flow_task(
            session,
            session_store,
            flow_name="capability-execution",
            task_name="plan",
            status="failed",
            error=str(exc),
            message="capability_plan_failed",
        )
        _finalize_session_status(session, session_store, stopped_reason="repeated_tool")
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - provider errors should surface as CLI failures
        _mark_flow_task(
            session,
            session_store,
            flow_name="capability-execution",
            task_name="execute",
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            message="capability_execution_failed",
        )
        _finalize_session_status(session, session_store, stopped_reason="repeated_tool")
        print(f"error: capability execution failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    terminal_status, exit_code = _capability_result_outcome(execution_result, rollback_result)
    required_success_missing = (
        exit_code == 0 and _required_jailbreak_success_missing(args, execution_result)
    )
    if required_success_missing:
        exit_code = 3
    _record_capability_lifecycle_knowledge(
        config,
        session,
        execution_result,
        rollback_result,
    )
    llm_jailbreak_knowledge = _record_llm_jailbreak_strategy_knowledge(
        config,
        session,
        target,
        execution_result,
    )
    compatibility_payload = getattr(args, "compatibility_payload", None)
    supplemental_results = getattr(args, "supplemental_artifact_results", ()) or ()
    extra_results: list[dict[str, Any]] = []
    if isinstance(compatibility_payload, Mapping):
        extra_results.append(dict(compatibility_payload))
    extra_results.extend(dict(item) for item in supplemental_results if isinstance(item, Mapping))
    for extra_result in extra_results:
        tool_results.append(extra_result)
        for artifact_path in _record_artifacts(session, session_store, extra_result):
            if artifact_path not in artifact_paths:
                artifact_paths.append(artifact_path)

    failure_phase = _capability_failure_phase(execution_result)
    plan_task_status = "succeeded"
    if failure_phase in {"resolve", "support", "plan"}:
        plan_task_status = "skipped" if terminal_status == "skipped" else "failed"
    validation_task_status = "succeeded"
    if failure_phase in {"resolve", "support", "plan"}:
        validation_task_status = "skipped"
    elif failure_phase == "validate":
        validation_task_status = "failed"
    execute_task_status = "succeeded"
    if failure_phase in {"resolve", "support", "plan", "validate"}:
        execute_task_status = "skipped"
    elif failure_phase == "execute" or (terminal_status == "failed" and failure_phase != "collect_artifacts"):
        execute_task_status = "failed"
    elif terminal_status == "skipped":
        execute_task_status = "skipped"

    _append_observation(
        tool_results,
        None,
        session,
        session_store,
        "capability_plan",
        {
            "capability": args.capability,
            "action": args.action,
            "provider": getattr(provider, "provider_name", None),
            "sample": str(sample_path) if sample_path is not None else None,
            "pid": args.pid,
            "params": params,
        },
        {
            "tool": "capability_plan",
            "status": "ok" if plan_task_status == "succeeded" else plan_task_status,
            "data": plan.to_dict() if hasattr(plan, "to_dict") else dict(plan or {}),
        },
    )
    _mark_flow_task(
        session,
        session_store,
        flow_name="capability-execution",
        task_name="plan",
        status=plan_task_status,
        result={"provider": getattr(provider, "provider_name", None), "step_count": len(getattr(plan, "steps", []) or [])},
        message="capability_plan_completed",
    )

    _append_observation(
        tool_results,
        None,
        session,
        session_store,
        "capability_validate",
        {
            "capability": args.capability,
            "action": args.action,
            "provider": getattr(provider, "provider_name", None),
        },
        {
            "tool": "capability_validate",
            "status": "ok" if validation_task_status == "succeeded" else validation_task_status,
            "data": validation.to_dict() if hasattr(validation, "to_dict") else dict(validation or {}),
        },
    )
    _mark_flow_task(
        session,
        session_store,
        flow_name="capability-execution",
        task_name="validate",
        status=validation_task_status,
        result={
            "ok": bool(getattr(validation, "ok", False)),
            "warning_count": len(getattr(validation, "warnings", []) or []),
            "error_count": len(getattr(validation, "errors", []) or []),
        },
        message="capability_validation_completed",
    )

    _append_observation(
        tool_results,
        None,
        session,
        session_store,
        "capability_execute",
        {
            "capability": args.capability,
            "action": args.action,
            "provider": getattr(provider, "provider_name", None),
            "rollback_requested": bool(args.rollback),
        },
        execution_result,
    )
    _mark_flow_task(
        session,
        session_store,
        flow_name="capability-execution",
        task_name="execute",
        status=execute_task_status,
        result={
            "status": getattr(execution_result, "status", "unknown"),
            "artifact_count": len(artifact_paths),
        },
        message="capability_execute_completed",
    )

    if rollback_result is not None:
        _append_observation(
            tool_results,
            None,
            session,
            session_store,
            "capability_rollback",
            {
                "capability": args.capability,
                "action": args.action,
                "provider": getattr(provider, "provider_name", None),
            },
            {
                "tool": "capability_rollback",
                "status": "ok" if getattr(rollback_result, "ok", False) else "failed",
                "data": rollback_result.to_dict()
                if hasattr(rollback_result, "to_dict")
                else dict(rollback_result or {}),
            },
        )

    _mark_flow_task(
        session,
        session_store,
        flow_name="capability-execution",
        task_name="collect-artifacts",
        status="failed" if failure_phase == "collect_artifacts" else "succeeded",
        result={"artifact_count": len(artifact_paths), "artifacts": [str(item) for item in artifact_paths]},
        error=(
            str((getattr(execution_result, "provenance", {}) or {}).get("failure", {}).get("reason") or "")
            if failure_phase == "collect_artifacts"
            else None
        ),
        message="capability_artifacts_collected",
    )

    flow = _find_flow(session, "capability-execution")
    if flow is not None and hasattr(flow, "set_status"):
        flow.set_status(terminal_status)
    if hasattr(session, "set_status"):
        session.set_status(terminal_status)
    outcome_metadata = _ensure_session_metadata(session)
    outcome_metadata["capability_outcome"] = {
        "provider_status": getattr(execution_result, "status", "unknown"),
        "session_status": terminal_status,
        "exit_code": exit_code,
        "failure_phase": failure_phase,
    }

    evidence_manifest = _write_evidence_manifest(
        session,
        session_store,
        sample_path if sample_path is not None else None,
        out_dir,
        tool_results,
    )
    if session_store is not None:
        session_store.save(session)

    report_builder_cls = _load_symbol("ReportBuilder")
    report_builder = _instantiate(report_builder_cls, session, tool_results, {}, config=config, out_dir=out_dir)
    report_data = _call_first(report_builder, ("build", "render"))
    section_name = _capability_section_name(args.capability)
    section_payload = _capability_section_payload(
        capability_name=args.capability,
        action=args.action,
        target=target,
        provider=provider,
        validation=validation,
        result=execution_result,
        rollback_result=rollback_result,
        artifact_paths=artifact_paths,
    )
    if llm_jailbreak_knowledge:
        section_payload["knowledge"] = dict(llm_jailbreak_knowledge)
    report_data[section_name] = section_payload
    metadata = _ensure_session_metadata(session)
    report_context = metadata.get("report_context")
    if not isinstance(report_context, dict):
        report_context = {}
        metadata["report_context"] = report_context
    report_context[section_name] = dict(section_payload)
    _finalize_platform_core_artifacts(
        report_data,
        out_dir,
        sample_path=str(sample_path) if sample_path is not None else None,
    )
    refreshed_manifest = _write_evidence_manifest(
        session,
        session_store,
        sample_path if sample_path is not None else None,
        out_dir,
        tool_results,
    )
    report_data["evidence_integrity"] = _session_evidence_integrity(session)
    if sample_path is not None and terminal_status == "succeeded":
        _persist_knowledge(config, sample_path, session, out_dir, report_data, tool_results)

    report_json = out_dir / "report.json"
    report_md = out_dir / "report.md"
    report_json.write_text(json.dumps(report_data, default=str, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown = report_builder.to_markdown() if hasattr(report_builder, "to_markdown") else "# Reverse Analysis Report\n"
    markdown += _capability_markdown_section(args.capability, section_payload)
    report_md.write_text(markdown, encoding="utf-8")

    _mark_flow_task(
        session,
        session_store,
        flow_name="capability-execution",
        task_name="report",
        status="succeeded",
        result={"report_json": str(report_json), "report_md": str(report_md)},
        message="capability_report_generated",
    )
    _finalize_session_status(session, session_store, stopped_reason="final_answer")
    flow = _find_flow(session, "capability-execution")
    if flow is not None and hasattr(flow, "set_status"):
        flow.set_status(terminal_status)
    if hasattr(session, "set_status"):
        session.set_status(terminal_status)

    session.artifacts.extend(
        [
            {"name": "report.json", "path": str(report_json), "kind": "report"},
            {"name": "report.md", "path": str(report_md), "kind": "report"},
        ]
    )
    if session_store is not None:
        session_store.save(session)

    payload = {
        "session_id": session.session_id,
        "out_dir": str(out_dir),
        "capability": args.capability,
        "action": args.action,
        "provider": (
            getattr(execution_result, "provider", None)
            or getattr(provider, "provider_name", None)
            or getattr(args, "provider", None)
        ),
        "validation": validation.to_dict() if hasattr(validation, "to_dict") else dict(validation or {}),
        "result": execution_result.to_dict() if hasattr(execution_result, "to_dict") else dict(execution_result or {}),
        "rollback": (
            rollback_result.to_dict()
            if rollback_result is not None and hasattr(rollback_result, "to_dict")
            else (dict(rollback_result or {}) if rollback_result is not None else None)
        ),
        "artifacts": [str(report_json), str(report_md), *artifact_paths],
    }
    if evidence_manifest is not None and str(evidence_manifest) not in payload["artifacts"]:
        payload["artifacts"].append(str(evidence_manifest))
    if refreshed_manifest is not None and str(refreshed_manifest) not in payload["artifacts"]:
        payload["artifacts"].append(str(refreshed_manifest))
    output_payload = payload
    if isinstance(compatibility_payload, Mapping):
        output_payload = _merge_capability_compatibility_payload(
            payload,
            compatibility_payload,
            preserve_success_status=bool(getattr(args, "compatibility_preserve_success_status", False)),
            refresh_patch_data=bool(getattr(args, "compatibility_refresh_patch_data", False)),
        )
    _print_json_payload(output_payload)
    if required_success_missing:
        print(
            "error: jailbreak campaign completed without a confirmed breakthrough",
            file=sys.stderr,
        )
    elif exit_code:
        result_payload = payload["result"] if isinstance(payload.get("result"), Mapping) else {}
        report_section = (
            result_payload.get("report_section")
            if isinstance(result_payload.get("report_section"), Mapping)
            else {}
        )
        reason = report_section.get("reason") or result_payload.get("reason") or getattr(
            execution_result,
            "status",
            "capability execution did not succeed",
        )
        print(f"error: capability execution did not succeed: {reason}", file=sys.stderr)
    return exit_code


def _jailbreak_extra_body(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        payload = json.loads(str(value))
    except json.JSONDecodeError as exc:
        raise ValueError(f"--extra-body must be a JSON object: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("--extra-body must be a JSON object")
    return dict(payload)


def jailbreak_run_command(args: argparse.Namespace) -> int:
    """Run an active adaptive jailbreak campaign through the audited registry."""

    if TargetIdentity is None:
        print("Model-jailbreak capability runtime is unavailable.", file=sys.stderr)
        return 3
    try:
        from .llm_jailbreak import configure_campaign, load_campaign

        campaign_path = Path(args.campaign).resolve()
        campaign = load_campaign(campaign_path)
        extra_body = _jailbreak_extra_body(getattr(args, "extra_body", None))
    except (OSError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out_root = Path(args.out).expanduser().resolve()
    params = [
        f"campaign_path={json.dumps(str(campaign_path), ensure_ascii=False)}",
    ]
    for argument_name, parameter_name in (
        ("base_url", "base_url"),
        ("model", "model"),
        ("api_key_env", "api_key_env"),
        ("timeout", "timeout"),
        ("max_attempts", "max_attempts"),
        ("max_rounds", "max_rounds"),
    ):
        value = getattr(args, argument_name, None)
        if value is not None:
            params.append(
                f"{parameter_name}={json.dumps(value, ensure_ascii=False)}"
            )

    strategies = list(getattr(args, "strategies", None) or [])
    if strategies:
        params.append(f"strategies={json.dumps(strategies, ensure_ascii=False)}")

    attack_modes = getattr(args, "attack_modes", None)
    semantic_judge = getattr(args, "semantic_judge", None)
    judge_model = getattr(args, "judge_model", None)
    instruction_profile = getattr(args, "instruction_profile", None)
    instruction_files = getattr(args, "instruction_files", None)

    options: dict[str, Any] = {}
    for argument_name, option_name in (
        ("temperature", "temperature"),
        ("max_tokens", "max_tokens"),
        ("max_retries", "max_retries"),
        ("retry_backoff_seconds", "retry_backoff_seconds"),
        ("requests_per_minute", "requests_per_minute"),
    ):
        value = getattr(args, argument_name, None)
        if value is not None:
            options[option_name] = value
    if extra_body is not None:
        options["extra_body"] = extra_body
    if options:
        params.append(f"options={json.dumps(options, ensure_ascii=False)}")

    try:
        configured_campaign = configure_campaign(
            campaign,
            base_url=getattr(args, "base_url", None),
            model=getattr(args, "model", None),
            api_key_env=getattr(args, "api_key_env", None),
            timeout=getattr(args, "timeout", None),
            max_attempts=getattr(args, "max_attempts", None),
            max_rounds=getattr(args, "max_rounds", None),
            strategies=strategies or None,
            attack_modes=attack_modes,
            semantic_judge=semantic_judge,
            judge_model=judge_model,
            instruction_profile=instruction_profile,
            instruction_files=instruction_files,
            options=options or None,
        )
    except (TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for parameter_name, explicit_value, effective_value in (
        ("attack_modes", attack_modes, list(configured_campaign.attack_modes)),
        ("semantic_judge", semantic_judge, configured_campaign.semantic_judge),
        ("judge_model", judge_model, configured_campaign.judge_model),
        (
            "instruction_profile",
            instruction_profile,
            configured_campaign.instruction_profile,
        ),
        (
            "instruction_files",
            instruction_files,
            list(configured_campaign.instruction_files),
        ),
    ):
        if explicit_value is not None:
            params.append(
                f"{parameter_name}={json.dumps(effective_value, ensure_ascii=False)}"
            )

    checkpoint_argument = getattr(args, "checkpoint", None)
    checkpoint_path = (
        Path(checkpoint_argument).expanduser().resolve()
        if checkpoint_argument is not None
        else (
            out_root
            / "llm_jailbreak"
            / "checkpoints"
            / f"{configured_campaign.fingerprint()}.json"
        ).resolve()
    )
    params.insert(
        1,
        f"checkpoint_path={json.dumps(str(checkpoint_path), ensure_ascii=False)}",
    )

    resume = bool(getattr(args, "resume", False))
    if resume:
        params.append("resume=true")
    model = configured_campaign.target.model
    base_url = configured_campaign.target.base_url
    target = TargetIdentity(
        kind="model",
        display_name=model,
        metadata={
            "model": model,
            "base_url": base_url,
            "campaign_id": configured_campaign.id,
            "campaign_path": str(campaign_path),
            "campaign_fingerprint": configured_campaign.fingerprint(),
            "checkpoint_path": str(checkpoint_path),
            "attack_modes": list(configured_campaign.attack_modes),
            "semantic_judge": configured_campaign.semantic_judge,
            "judge_model": configured_campaign.judge_model,
            "instruction_profile": configured_campaign.instruction_profile,
            "instruction_files": list(configured_campaign.instruction_files),
        },
    )
    forwarded = argparse.Namespace(
        capability="llm_jailbreak",
        action="resume" if resume else "run",
        sample=None,
        pid=None,
        out=args.out,
        provider=getattr(args, "provider", None) or "openai_compatible_jailbreak",
        param=params,
        rollback=False,
        target_identity_override=target,
        entrypoint="cli.jailbreak.run",
        require_success=bool(getattr(args, "require_success", False)),
    )
    return capability_run_command(forwarded)


def jailbreak_validate_command(args: argparse.Namespace) -> int:
    """Validate and normalize a jailbreak campaign without contacting a model."""

    try:
        from .llm_jailbreak import load_campaign

        campaign = load_campaign(Path(args.campaign).resolve())
    except (OSError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    payload = campaign.to_dict()
    if bool(getattr(args, "json", False)):
        _print_json_payload(payload)
    else:
        print(
            f"valid campaign={campaign.id} model={campaign.target.model} "
            f"rounds={campaign.max_rounds} strategies={len(campaign.strategies)}"
        )
    return 0


def jailbreak_strategies_command(args: argparse.Namespace) -> int:
    """List built-in active jailbreak strategy identifiers."""

    try:
        from .llm_jailbreak import SUPPORTED_STRATEGIES
    except ImportError as exc:
        print(f"error: model-jailbreak core is unavailable: {exc}", file=sys.stderr)
        return 3
    if bool(getattr(args, "json", False)):
        _print_json_payload({"strategies": list(SUPPORTED_STRATEGIES)})
    else:
        for strategy in SUPPORTED_STRATEGIES:
            print(strategy)
    return 0


def jailbreak_profiles_command(args: argparse.Namespace) -> int:
    """List repository-backed instruction profile identifiers."""

    try:
        from .llm_jailbreak import list_instruction_profiles
    except ImportError as exc:
        print(f"error: model-jailbreak core is unavailable: {exc}", file=sys.stderr)
        return 3
    profiles = list_instruction_profiles()
    if bool(getattr(args, "json", False)):
        _print_json_payload({"profiles": list(profiles)})
    else:
        for profile in profiles:
            print(profile)
    return 0


def jailbreak_doctor_command(args: argparse.Namespace) -> int:
    """Probe a configured endpoint without starting a campaign."""

    try:
        from .llm_jailbreak import run_doctor

        result = run_doctor(
            base_url=args.base_url,
            model=args.model,
            api_key_env=args.api_key_env,
            timeout_seconds=args.timeout,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    payload = result.to_dict()
    if bool(getattr(args, "json", False)):
        _print_json_payload(payload)
    else:
        print(f"doctor={result.status} model={result.model} checks={len(result.checks)}")
    return 0


def jailbreak_promote_command(args: argparse.Namespace) -> int:
    """Validate retained live endpoint evidence for release promotion."""

    try:
        from .llm_jailbreak import promote_output

        result = promote_output(args.path, secret_env_names=args.secret_env)
    except (OSError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if bool(getattr(args, "json", False)):
        _print_json_payload(result.to_dict())
    else:
        print(
            f"promotion={result.status} checks={len(result.checks)} "
            f"record={result.promotion_path}"
        )
    return 0 if result.ok else 4


def _dedicated_capability_command(args: argparse.Namespace) -> int:
    """Normalize ergonomic command groups into the audited capability runner."""

    params = list(getattr(args, "param", None) or [])
    for argument_name, parameter_name in getattr(args, "capability_param_fields", ()):
        value = getattr(args, argument_name, None)
        if value is None:
            continue
        if getattr(args, "capability", None) == "memory_runtime":
            try:
                value = _normalize_memory_cli_parameter(args, parameter_name, value)
            except (UnicodeEncodeError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
        params.append(f"{parameter_name}={json.dumps(value, ensure_ascii=False)}")
    forwarded = argparse.Namespace(
        capability=args.capability,
        action=args.action,
        sample=getattr(args, "sample", None),
        pid=getattr(args, "pid", None),
        out=args.out,
        provider=getattr(args, "provider", None),
        param=params,
        rollback=bool(getattr(args, "rollback", False)),
    )
    return capability_run_command(forwarded)


_MEMORY_PROTECTION_ALIASES = {
    "none": "PAGE_NOACCESS",
    "r": "PAGE_READONLY",
    "rw": "PAGE_READWRITE",
    "wc": "PAGE_WRITECOPY",
    "x": "PAGE_EXECUTE",
    "rx": "PAGE_EXECUTE_READ",
    "rwx": "PAGE_EXECUTE_READWRITE",
    "xwc": "PAGE_EXECUTE_WRITECOPY",
}


def _normalize_memory_cli_parameter(
    args: argparse.Namespace,
    parameter_name: str,
    value: Any,
) -> Any:
    """Translate human-oriented memory CLI values into provider inputs."""

    action = str(getattr(args, "action", "") or "").casefold()
    if action == "scan" and parameter_name == "pattern":
        pattern_type = str(getattr(args, "pattern_type", "aob") or "aob").casefold()
        if pattern_type == "ascii":
            return _format_memory_cli_bytes(str(value).encode("ascii"))
        if pattern_type == "utf16":
            return _format_memory_cli_bytes(str(value).encode("utf-16-le"))
        if pattern_type == "pointer":
            pointer_size = int(getattr(args, "pointer_size", 8))
            pointer = int(str(value).strip(), 0)
            if pointer < 0 or pointer >= 1 << (pointer_size * 8):
                raise ValueError(f"pointer value does not fit in {pointer_size} bytes")
            return _format_memory_cli_bytes(
                pointer.to_bytes(pointer_size, byteorder="little", signed=False)
            )
    if action == "write" and parameter_name == "data":
        encoding = str(getattr(args, "encoding", "hex") or "hex").casefold()
        codecs = {
            "ascii": "ascii",
            "utf8": "utf-8",
            "utf16le": "utf-16-le",
        }
        if encoding in codecs:
            return _format_memory_cli_bytes(str(value).encode(codecs[encoding]))
    if parameter_name in {"protection", "expected_protection"}:
        normalized = str(value).strip()
        alias = _MEMORY_PROTECTION_ALIASES.get(normalized.casefold())
        if alias is not None:
            return alias
        if normalized.casefold().startswith("page_"):
            return normalized.upper()
    return value


def _format_memory_cli_bytes(value: bytes) -> str:
    if not value:
        raise ValueError("memory byte pattern must be non-empty")
    return " ".join(f"{octet:02X}" for octet in value)


def _hook_capability_command(args: argparse.Namespace) -> int:
    """Translate the hook CLI contract into the hook provider contract."""

    try:
        hook_specification = _load_json_object(args.plan, label="hook plan")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    duration_ms = int(round(float(args.duration) * 1000.0))
    requested_backend = str(args.backend or "auto").casefold()
    provider = getattr(args, "provider", None)
    if requested_backend == "frida":
        provider = "frida_hook_runtime"
    elif requested_backend == "win32":
        # No Win32 backend is registered. Resolving this explicit provider
        # produces a durable failed capability record instead of using Frida.
        provider = "win32_hook_runtime"

    params = list(getattr(args, "param", None) or [])
    params.extend(
        (
            f"hook_specification={json.dumps(hook_specification, ensure_ascii=False)}",
            f"duration_ms={json.dumps(duration_ms)}",
            f"requested_backend={json.dumps(requested_backend)}",
        )
    )
    forwarded = argparse.Namespace(
        capability="hook_runtime",
        action="hook-trace",
        sample=getattr(args, "sample", None),
        pid=getattr(args, "pid", None),
        out=args.out,
        provider=provider,
        param=params,
        rollback=bool(getattr(args, "rollback", False)),
    )
    return capability_run_command(forwarded)


def _analysis_alias_command(args: argparse.Namespace) -> int:
    """Run the normal evidence pipeline for a domain-specific CLI alias."""

    forwarded = ["analyze", str(args.sample), "--out", str(args.out)]
    for option in getattr(args, "analysis_options", ()):
        if bool(getattr(args, option.replace("-", "_"), False)):
            forwarded.append(f"--{option}")
    for option in getattr(args, "analysis_value_options", ()):
        value = getattr(args, option.replace("-", "_"), None)
        if value is None:
            continue
        values = value if isinstance(value, (list, tuple)) else (value,)
        for item in values:
            forwarded.extend((f"--{option}", str(item)))
    return main(forwarded)


def _protocol_stage_args(args: argparse.Namespace, out_dir: Path) -> dict[str, Any]:
    """Return the shared bounded-import arguments for protocol CLI stages."""

    requested_format = getattr(args, "format", "auto")
    return {
        "source_format": None if requested_format == "auto" else requested_format,
        "max_bytes": int(args.max_bytes),
        "max_packets": int(args.max_packets),
        "max_messages": int(args.max_messages),
        "max_message_bytes": int(args.max_message_bytes),
        "out_dir": str(out_dir),
    }


def _protocol_message_artifact_result(inference: Mapping[str, Any], out_dir: Path) -> dict[str, Any]:
    """Persist one bounded JSON artifact per normalized protocol message."""

    message_dir = out_dir / "protocol" / "messages"
    message_dir.mkdir(parents=True, exist_ok=True)
    messages = [dict(item) for item in inference.get("messages") or [] if isinstance(item, Mapping)]
    artifacts: list[dict[str, Any]] = []
    if messages:
        for index, message in enumerate(messages, start=1):
            path = message_dir / f"message-{index:04d}.json"
            path.write_text(
                json.dumps(message, ensure_ascii=False, indent=2, default=str) + "\n",
                encoding="utf-8",
            )
            artifacts.append(
                {
                    "name": f"protocol/messages/{path.name}",
                    "path": str(path),
                    "kind": "protocol-message",
                }
            )
    else:
        path = message_dir / "index.json"
        path.write_text(
            json.dumps({"schema_version": 1, "message_count": 0, "messages": []}, indent=2) + "\n",
            encoding="utf-8",
        )
        artifacts.append(
            {
                "name": "protocol/messages/index.json",
                "path": str(path),
                "kind": "protocol-message-index",
            }
        )
    return {
        "status": "ok",
        "message_count": len(messages),
        "artifacts": artifacts,
    }


def _platform_core_artifact_result(platform_core: Mapping[str, Any]) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    for key, kind in (("semantic_ir", "semantic-ir"), ("evidence_graph", "evidence-graph")):
        section = platform_core.get(key)
        if not isinstance(section, Mapping) or not section.get("path"):
            continue
        path = Path(str(section["path"]))
        artifacts.append({"name": path.name, "path": str(path), "kind": kind})
    return {
        "status": "ok" if artifacts else "unavailable",
        "artifacts": artifacts,
    }


def protocol_command(args: argparse.Namespace) -> int:
    """Run the complete passive protocol evidence pipeline for one source."""

    config = load_config()
    ensure_runtime_dirs(config)
    source = Path(args.source).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    session = _new_session(source, out_dir, 4)
    missing: list[str] = []
    loaded: dict[str, Any] = {}
    for symbol in ("ToolExecutor", "ReportBuilder"):
        try:
            loaded[symbol] = _load_symbol(symbol)
        except RuntimeError as exc:
            missing.append(str(exc))
    if missing:
        print("error: protocol runtime is incomplete.", file=sys.stderr)
        for item in missing:
            print(f"- {item}", file=sys.stderr)
        return 3

    trace_logger = TraceLogger(out_dir / "trace.jsonl") if TraceLogger is not None else None
    session_store = SessionStore(out_dir, trace_logger=trace_logger) if SessionStore is not None else None
    if session_store is not None:
        session_store.save(session)

    tool_executor = _instantiate(loaded["ToolExecutor"], config=config, out_dir=out_dir)
    if register_builtin_tools is not None:
        register_builtin_tools(tool_executor)

    tool_results: list[dict[str, Any]] = []
    result_container = argparse.Namespace(tool_results=tool_results, stopped_reason="protocol_cli")
    artifact_paths: list[str] = []
    shared = _protocol_stage_args(args, out_dir)

    capture_args = {"path": str(source), **shared}
    capture_result = tool_executor.execute("protocol_capture", **capture_args)
    _append_observation(
        tool_results,
        result_container,
        session,
        session_store,
        "protocol_capture",
        capture_args,
        capture_result,
    )
    artifact_paths.extend(_record_artifacts(session, session_store, capture_result))
    capture_payload = _result_payload(capture_result)
    if not isinstance(capture_payload, Mapping):
        capture_payload = {}

    infer_args = {"capture": dict(capture_payload), **shared}
    infer_result = tool_executor.execute("protocol_infer", **infer_args)
    _append_observation(
        tool_results,
        result_container,
        session,
        session_store,
        "protocol_infer",
        {**shared, "capture": "protocol_capture"},
        infer_result,
    )
    artifact_paths.extend(_record_artifacts(session, session_store, infer_result))
    inference = _result_payload(infer_result)
    if not isinstance(inference, Mapping):
        inference = {}

    summarize_args = {"inference": dict(inference), **shared}
    summarize_result = tool_executor.execute("protocol_summarize", **summarize_args)
    _append_observation(
        tool_results,
        result_container,
        session,
        session_store,
        "protocol_summarize",
        {**shared, "inference": "protocol_infer"},
        summarize_result,
    )
    artifact_paths.extend(_record_artifacts(session, session_store, summarize_result))

    analyze_args = {
        "path": str(source),
        "capture": dict(inference),
        **shared,
    }
    analyze_result = tool_executor.execute("protocol_analyze", **analyze_args)
    _append_observation(
        tool_results,
        result_container,
        session,
        session_store,
        "protocol_analyze",
        {**shared, "path": str(source), "capture": "protocol_infer"},
        analyze_result,
    )
    artifact_paths.extend(_record_artifacts(session, session_store, analyze_result))

    message_result = _protocol_message_artifact_result(inference, out_dir)
    _append_observation(
        tool_results,
        result_container,
        session,
        session_store,
        "protocol_message_artifacts",
        {"source": "protocol_infer", "out_dir": str(out_dir)},
        message_result,
    )
    artifact_paths.extend(_record_artifacts(session, session_store, message_result))

    protocol_outcome = _aggregate_stage_outcome(
        tool_results,
        required_tools={
            "protocol_capture",
            "protocol_infer",
            "protocol_summarize",
            "protocol_analyze",
        },
        require_all=True,
    )
    _ensure_session_metadata(session)["protocol_outcome"] = dict(protocol_outcome)

    _mark_flow_task(
        session,
        session_store,
        flow_name="binary-analysis",
        task_name="identify",
        status="succeeded",
        result={"source": str(source), "exists": source.exists()},
        message="protocol_source_identified",
    )
    _mark_flow_task(
        session,
        session_store,
        flow_name="binary-analysis",
        task_name="analyze",
        status="failed" if protocol_outcome["hard_failure"] else "succeeded",
        result={
            "tool_count": len(tool_results),
            "requested_command": args.protocol_command,
            "protocol_outcome": protocol_outcome,
        },
        error=_stage_outcome_error(protocol_outcome),
        message="protocol_analysis_failed" if protocol_outcome["hard_failure"] else "protocol_analysis_completed",
    )

    report_builder = _instantiate(
        loaded["ReportBuilder"],
        session,
        tool_results,
        {},
        config=config,
        out_dir=out_dir,
    )
    report_data = _call_first(report_builder, ("build", "render"))
    platform_core = _finalize_platform_core_artifacts(
        report_data,
        out_dir,
        sample_path=str(source),
    )
    core_result = _platform_core_artifact_result(platform_core)
    _append_observation(
        tool_results,
        result_container,
        session,
        session_store,
        "platform_core_finalize",
        {"out_dir": str(out_dir)},
        core_result,
    )
    artifact_paths.extend(_record_artifacts(session, session_store, core_result))

    report_data = _call_first(report_builder, ("build", "render"))
    _finalize_platform_core_artifacts(report_data, out_dir, sample_path=str(source))
    evidence_manifest = _write_evidence_manifest(session, session_store, source, out_dir, tool_results)
    if evidence_manifest is not None:
        artifact_paths.append(str(evidence_manifest))
    report_data["evidence_integrity"] = _session_evidence_integrity(session)
    report_data["protocol_outcome"] = dict(protocol_outcome)

    if source.exists():
        _persist_knowledge(config, source, session, out_dir, report_data, tool_results)

    report_json = out_dir / "report.json"
    report_md = out_dir / "report.md"
    report_json.write_text(
        json.dumps(report_data, default=str, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if hasattr(report_builder, "to_markdown"):
        report_md.write_text(report_builder.to_markdown(), encoding="utf-8")

    _mark_flow_task(
        session,
        session_store,
        flow_name="binary-analysis",
        task_name="report",
        status="succeeded",
        result={"report_json": str(report_json), "report_md": str(report_md)},
        message="protocol_report_generated",
    )
    if hasattr(session, "set_status"):
        session.set_status("failed" if protocol_outcome["hard_failure"] else "succeeded")
    _finalize_session_status(session, session_store, stopped_reason="protocol_cli")
    session.artifacts.extend(
        [
            {"name": "report.json", "path": str(report_json), "kind": "report"},
            {"name": "report.md", "path": str(report_md), "kind": "report"},
        ]
    )
    if session_store is not None:
        session_store.save(session)

    _print_json_payload(
        {
            "session_id": session.session_id,
            "command": args.protocol_command,
            "source": str(source),
            "status": protocol_outcome["status"],
            "protocol_outcome": protocol_outcome,
            "out_dir": str(out_dir),
            "artifacts": [str(report_json), str(report_md), *artifact_paths],
        }
    )
    return 2 if protocol_outcome["hard_failure"] else 0


def _experiment_context(args: argparse.Namespace) -> tuple[AnalyzerConfig, Any] | None:
    if ExperimentStore is None:
        print("Experiment control plane is unavailable because runtime modules could not be imported.", file=sys.stderr)
        return None
    config = load_config(args.workspace)
    return config, ExperimentStore(config.workspace)


_LOCAL_RUNNER_LOCATION_ENV = (
    "REVERSE_ANALYZER_KNOWLEDGE_DIR",
    "REVERSE_ANALYZER_SESSIONS_DIR",
    "REVERSE_ANALYZER_REPORTS_DIR",
)


def _local_runner_environment(workspace: str | Path) -> Dict[str, str]:
    """Isolate a local child analysis from parent workspace location overrides."""

    environment = dict(os.environ)
    for variable in _LOCAL_RUNNER_LOCATION_ENV:
        environment.pop(variable, None)
    environment["REVERSE_ANALYZER_WORKSPACE"] = str(workspace)
    return environment


def _experiment_options(args: argparse.Namespace) -> Dict[str, Any]:
    options: Dict[str, Any] = {}
    if args.dynamic:
        options.update(
            {
                "dynamic": True,
                "dynamic_backend": args.dynamic_backend,
                "dynamic_profile": args.dynamic_profile,
                "dynamic_duration": args.dynamic_duration,
            }
        )
    gui_enabled = bool(args.gui or args.gui_runtime or args.gui_visual or args.reconstruct_gui or args.gui_interaction_trace)
    if gui_enabled:
        options.update(
            {
                "gui": True,
                "gui_runtime": bool(args.gui_runtime),
                "gui_visual": bool(args.gui_visual),
                "reconstruct_gui": bool(args.reconstruct_gui),
                "gui_target": args.gui_target,
                "gui_interaction_trace": args.gui_interaction_trace,
            }
        )
    if args.reconstruct:
        options["reconstruct"] = True
    if args.memory_analysis or args.memory_plan:
        options["memory_analysis"] = True
        if args.memory_plan:
            options["memory_plan"] = args.memory_plan
    return {key: value for key, value in options.items() if value is not None and value is not False}


def _print_json_payload(payload: Mapping[str, Any]) -> None:
    print(json.dumps(dict(payload), ensure_ascii=False, indent=2, default=str))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_directory(path: Path) -> str:
    """Hash a directory tree deterministically for rebuild preconditions."""

    digest = hashlib.sha256()
    for child in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        relative = child.relative_to(path).as_posix().encode("utf-8", errors="surrogateescape")
        if child.is_symlink():
            digest.update(b"L\0" + relative + b"\0")
            digest.update(os.readlink(child).encode("utf-8", errors="surrogateescape"))
        elif child.is_dir():
            digest.update(b"D\0" + relative + b"\0")
        elif child.is_file():
            size = child.stat().st_size
            digest.update(b"F\0" + relative + b"\0" + str(size).encode("ascii") + b"\0")
            with child.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def _ensure_session_metadata(session: Any) -> dict[str, Any]:
    metadata = getattr(session, "metadata", None)
    if not isinstance(metadata, dict):
        metadata = dict(metadata) if isinstance(metadata, Mapping) else {}
        setattr(session, "metadata", metadata)
    return metadata


def _append_capability_audit_record(session: Any, record: Any) -> dict[str, Any]:
    metadata = _ensure_session_metadata(session)
    capability_audit = metadata.get("capability_audit")
    if not isinstance(capability_audit, dict):
        capability_audit = {}
        metadata["capability_audit"] = capability_audit
    records = capability_audit.get("records")
    if not isinstance(records, list):
        records = []
        capability_audit["records"] = records
    payload = record.to_dict() if hasattr(record, "to_dict") else dict(record or {})
    records.append(payload)
    summary = summarize_audit_records(records) if callable(summarize_audit_records) else {"record_count": len(records)}
    capability_audit["record_count"] = len(records)
    capability_audit["summary"] = summary
    report_context = metadata.get("report_context")
    if not isinstance(report_context, dict):
        report_context = {}
        metadata["report_context"] = report_context
    report_context["capability_audit"] = {
        "record_count": capability_audit["record_count"],
        "records": [dict(item) for item in records if isinstance(item, Mapping)],
        "summary": dict(summary),
    }
    return capability_audit


def _latest_capability_audit_record(session: Any) -> Mapping[str, Any] | None:
    metadata = _ensure_session_metadata(session)
    capability_audit = metadata.get("capability_audit")
    records = capability_audit.get("records") if isinstance(capability_audit, Mapping) else None
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        return None
    for record in reversed(records):
        if isinstance(record, Mapping):
            return record
    return None


def _record_capability_lifecycle_knowledge(
    config: AnalyzerConfig,
    session: Any,
    execution_result: Any,
    rollback_result: Any,
) -> Mapping[str, Any] | None:
    """Record exactly one finalized provider lifecycle outcome in the KB."""

    metadata = _ensure_session_metadata(session)
    if KnowledgeBase is None or not callable(record_capability_lifecycle_outcome):
        metadata["capability_knowledge"] = {"status": "unavailable"}
        return None

    result_payload = _tool_result_dict(execution_result)
    result_mapping = result_payload if isinstance(result_payload, Mapping) else {}
    artifact_bundle = {
        "artifacts": list(result_mapping.get("artifacts") or []),
        "manifest_entries": list(result_mapping.get("evidence_manifest_entries") or []),
    }
    try:
        outcome = record_capability_lifecycle_outcome(
            KnowledgeBase(config.knowledge_dir),
            execution_result,
            artifact_bundle=artifact_bundle,
            rollback_result=rollback_result,
            audit_record=_latest_capability_audit_record(session),
        )
    except Exception as exc:  # noqa: BLE001 - knowledge persistence must not replace the provider outcome
        metadata["capability_knowledge"] = {
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}",
        }
        print(f"capability_knowledge.failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None

    if not isinstance(outcome, Mapping):
        metadata["capability_knowledge"] = {"status": "ignored"}
        return None
    metadata["capability_knowledge"] = {
        "status": "recorded",
        "capability": result_mapping.get("capability"),
        "provider": result_mapping.get("provider"),
        "action": result_mapping.get("action"),
        "lifecycle_status": result_mapping.get("status"),
        "outcome": dict(outcome),
    }
    return outcome


def _record_llm_jailbreak_strategy_knowledge(
    config: AnalyzerConfig,
    session: Any,
    target: Any,
    execution_result: Any,
) -> Mapping[str, Any] | None:
    """Persist one model-jailbreak outcome without exposing provider credentials."""

    result_payload = _tool_result_dict(execution_result)
    if not isinstance(result_payload, Mapping):
        return None
    if str(result_payload.get("capability") or "").strip().lower() != "llm_jailbreak":
        return None

    metadata = _ensure_session_metadata(session)
    if KnowledgeBase is None:
        metadata["llm_jailbreak_knowledge"] = {"status": "unavailable"}
        return None

    report_section = (
        result_payload.get("report_section")
        if isinstance(result_payload.get("report_section"), Mapping)
        else {}
    )
    source = {**result_payload, **dict(report_section)}
    strategy_value = source.get("strategy") or source.get("best_strategy") or "adaptive"
    if isinstance(strategy_value, Mapping):
        strategy_value = (
            strategy_value.get("name")
            or strategy_value.get("strategy")
            or strategy_value.get("key")
            or "adaptive"
        )
    elif isinstance(strategy_value, Sequence) and not isinstance(
        strategy_value,
        (str, bytes, bytearray),
    ):
        strategy_value = next((str(item) for item in strategy_value if item), "adaptive")

    target_payload = target.to_dict() if hasattr(target, "to_dict") else dict(target or {})
    target_metadata = (
        target_payload.get("metadata")
        if isinstance(target_payload.get("metadata"), Mapping)
        else {}
    )
    model = str(
        source.get("model")
        or target_metadata.get("model")
        or target_payload.get("display_name")
        or "unknown"
    )
    campaign_id = str(
        source.get("campaign_id")
        or target_metadata.get("campaign_id")
        or getattr(session, "session_id", "unknown")
    )
    success = source.get("success")
    raw_status = str(source.get("status") or "unknown").strip().lower()
    if success is True:
        status = "ok"
    elif raw_status in {"unavailable", "unsupported", "not_available", "skipped"}:
        status = "unavailable"
    else:
        status = "failed"

    try:
        knowledge = KnowledgeBase(config.knowledge_dir)
        record = knowledge.record_llm_jailbreak_strategy_result(
            str(strategy_value),
            model=model,
            status=status,
            score=_safe_float(source.get("score"), default=0.0),
            attempts=_safe_int(source.get("attempt_count"), default=0),
            latency_ms=_safe_float(source.get("latency_ms"), default=0.0),
            sample_id=campaign_id,
        )
        recommendation = knowledge.recommend_llm_jailbreak_strategy(model=model)
        summary = {
            "status": "recorded",
            "record": record,
            "recommendation": recommendation,
        }
        metadata["llm_jailbreak_knowledge"] = summary
        knowledge.append_session_summary(
            {
                "session_id": getattr(session, "session_id", None),
                "target": model,
                "status": status,
                "campaign_id": campaign_id,
                "llm_jailbreak_strategy_records": [record],
                "recommended_llm_jailbreak_strategy": recommendation,
            }
        )
        return summary
    except Exception as exc:  # noqa: BLE001 - campaign evidence remains valid if KB is unavailable
        metadata["llm_jailbreak_knowledge"] = {
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}",
        }
        print(
            f"llm_jailbreak_knowledge.failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return None


def _parse_capability_params(values: Sequence[str] | None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for item in values or []:
        if "=" not in str(item):
            raise ValueError(f"invalid capability param '{item}'; expected key=value")
        key, raw_value = str(item).split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"invalid capability param '{item}'; empty key")
        value = raw_value.strip()
        try:
            params[key] = json.loads(value)
        except json.JSONDecodeError:
            lowered = value.lower()
            if lowered == "true":
                params[key] = True
            elif lowered == "false":
                params[key] = False
            elif lowered == "null":
                params[key] = None
            else:
                params[key] = value
    return params


def _capability_target_identity(sample: str | None, pid: int | None) -> Any:
    if TargetIdentity is None:
        raise RuntimeError("Capability target model is not available.")
    sample_path = Path(sample).resolve() if sample else None
    kind = "process" if pid is not None and sample_path is None else "sample"
    display_name = sample_path.name if sample_path is not None else (f"pid:{pid}" if pid is not None else "capability-target")
    metadata: dict[str, Any] = {}
    sha256 = None
    if sample_path is not None:
        if sample_path.is_file():
            sha256 = _sha256_file(sample_path)
            metadata["exists"] = True
            metadata["target_type"] = "file"
        elif sample_path.is_dir():
            sha256 = _sha256_directory(sample_path)
            metadata["exists"] = True
            metadata["target_type"] = "directory"
        else:
            metadata["exists"] = False
    if pid is not None:
        metadata["pid"] = pid
    return TargetIdentity(
        kind=kind,
        path=str(sample_path) if sample_path is not None else None,
        pid=pid,
        sha256=sha256,
        display_name=display_name,
        metadata=metadata,
    )


def _new_capability_session(
    target: Any,
    out_dir: Path,
    capability_name: str,
    action: str,
    requested_provider: str | None = None,
) -> Any:
    try:
        from .core.models import Flow, ReverseSession, Task
    except Exception as exc:
        raise RuntimeError(f"ReverseSession models are not importable: {exc}") from exc

    session = ReverseSession(
        target=getattr(target, "path", None) or getattr(target, "display_name", None),
        metadata={
            "out_dir": str(out_dir),
            "capability": capability_name,
            "action": action,
            "requested_provider": requested_provider,
        },
    )
    flow = Flow(
        "capability-execution",
        "Capability provider execution flow",
        metadata={"capability": capability_name, "action": action},
    )
    flow.add_task(Task("plan", "Plan capability execution"))
    flow.add_task(Task("validate", "Validate capability execution plan"))
    flow.add_task(Task("execute", "Execute capability provider"))
    flow.add_task(Task("collect-artifacts", "Persist capability artifacts"))
    flow.add_task(Task("report", "Generate capability execution report"))
    session.add_flow(flow)
    if hasattr(session, "start"):
        session.start()
    if hasattr(flow, "start"):
        flow.start()
    return session


def _materialize_capability_artifacts(
    result: Any,
    bundle: Any,
    out_dir: Path,
    session: Any,
    session_store: Any,
) -> list[str]:
    artifacts = list(getattr(bundle, "artifacts", []) or [])
    manifest_entries = list(getattr(bundle, "manifest_entries", []) or [])
    materialized_artifacts: list[dict[str, Any]] = []
    materialized_entries: list[dict[str, Any]] = []
    paths: list[str] = []

    manifest_entry_lookup: dict[str, dict[str, Any]] = {}
    for entry in manifest_entries:
        payload = entry.to_dict() if hasattr(entry, "to_dict") else dict(entry or {})
        path_value = payload.get("path")
        if path_value:
            manifest_entry_lookup[str(path_value)] = payload

    artifact_lookup: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        payload = artifact.to_dict() if hasattr(artifact, "to_dict") else dict(artifact or {})
        path_value = payload.get("path")
        if not path_value:
            continue
        path = Path(path_value)
        destination = path if path.is_absolute() else out_dir / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = {
            "capability": getattr(result, "capability", None),
            "provider": getattr(result, "provider", None),
            "session_id": getattr(result, "session_id", None),
            "status": getattr(result, "status", None),
            "action": getattr(result, "action", None),
            "before_snapshot": dict(getattr(result, "before_snapshot", {}) or {}),
            "after_snapshot": dict(getattr(result, "after_snapshot", {}) or {}),
            "rollback_plan": dict(getattr(result, "rollback_plan", {}) or {}),
            "artifact": payload,
            "provenance": dict(getattr(result, "provenance", {}) or {}),
        }
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), Mapping) else {}
        provider_materialized = bool(metadata.get("materialized"))
        if provider_materialized and not destination.exists():
            raise FileNotFoundError(f"provider artifact was not materialized: {destination}")
        if not destination.exists():
            destination.write_text(
                json.dumps(content, ensure_ascii=False, indent=2, default=str) + "\n",
                encoding="utf-8",
            )
        manifest_payload = manifest_entry_lookup.get(str(path_value), {})
        artifact_record = {
            **manifest_payload,
            **payload,
            "path": str(destination),
            "name": payload.get("name") or destination.name,
            "tool": (
                payload.get("tool")
                or manifest_payload.get("tool")
                or getattr(result, "capability", None)
            ),
            "status": (
                payload.get("status")
                or manifest_payload.get("status")
                or getattr(result, "status", None)
            ),
            "role": (
                payload.get("role")
                or manifest_payload.get("role")
                or "capability_artifact"
            ),
        }
        materialized_artifacts.append(artifact_record)
        artifact_lookup[str(path_value)] = artifact_record
        paths.append(str(destination))
        if session_store is not None and hasattr(session_store, "record_artifact"):
            session_store.record_artifact(
                session,
                artifact_record["name"],
                path=str(destination),
                kind=str(artifact_record.get("kind") or "artifact"),
                data=artifact_record,
            )
        elif session is not None and hasattr(session, "artifacts"):
            session.artifacts.append(dict(artifact_record))

    for entry in manifest_entries:
        payload = entry.to_dict() if hasattr(entry, "to_dict") else dict(entry or {})
        path_value = payload.get("path")
        if path_value and str(path_value) in artifact_lookup:
            payload["path"] = artifact_lookup[str(path_value)]["path"]
        materialized_entries.append(payload)

    if hasattr(result, "artifacts"):
        result.artifacts = materialized_artifacts
    if hasattr(result, "evidence_manifest_entries"):
        result.evidence_manifest_entries = materialized_entries
    return paths


def _write_capability_audit_artifact(record: Any, out_dir: Path, session: Any, session_store: Any) -> str:
    path = out_dir / "capabilities" / f"{record.capability}_{record.action}_audit.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = record.to_dict() if hasattr(record, "to_dict") else dict(record or {})
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    artifact = {
        "name": path.name,
        "path": str(path),
        "kind": "capability_audit",
        "tool": getattr(record, "capability", None),
        "status": getattr(record, "status", None),
        "role": "capability_audit_record",
    }
    if session_store is not None and hasattr(session_store, "record_artifact"):
        session_store.record_artifact(session, path.name, path=str(path), kind="capability_audit", data=artifact)
    elif session is not None and hasattr(session, "artifacts"):
        session.artifacts.append(artifact)
    return str(path)


def _execute_capability_request(
    *,
    registry: Any,
    request: Any,
    out_dir: Path,
    session: Any,
    session_store: Any,
    audit_builder: Any,
    rollback: bool = False,
) -> tuple[Any, Any, Any, Any, Any, list[str]]:
    context = {
        "out_dir": str(out_dir),
        "session": session,
        "session_store": session_store,
    }

    def persist(
        plan: Any,
        validation: Any,
        result: Any,
        bundle: Any,
        rollback_result: Any = None,
    ) -> list[str]:
        artifact_paths = _materialize_capability_artifacts(
            result,
            bundle,
            out_dir,
            session,
            session_store,
        )
        record = audit_builder.build_record(plan=plan, result=result, validation=validation)
        if rollback_result is not None and hasattr(record, "add_event"):
            record.add_event(
                "rollback",
                "capability rollback completed",
                ok=getattr(rollback_result, "ok", False),
                restored=getattr(rollback_result, "restored", False),
                details=dict(getattr(rollback_result, "details", {}) or {}),
            )
        _append_capability_audit_record(session, record)
        audit_path = _write_capability_audit_artifact(record, out_dir, session, session_store)
        artifact_paths.append(audit_path)
        return artifact_paths

    try:
        provider = registry.resolve(request.capability, preferred=request.requested_provider)
    except Exception as exc:  # noqa: BLE001 - unresolved providers still need a durable audit record
        reason = str(exc) or type(exc).__name__
        provider_name = str(request.requested_provider or "unresolved")
        plan, validation, result, bundle = _capability_synthetic_failure(
            request,
            provider_name=provider_name,
            phase="resolve",
            reason=reason,
        )
        return None, plan, validation, result, None, persist(plan, validation, result, bundle)

    provider_name = str(getattr(provider, "provider_name", None) or type(provider).__name__)
    try:
        supported = not hasattr(provider, "supports") or bool(provider.supports(request, context=context))
    except Exception as exc:  # noqa: BLE001 - provider boundary must be represented as evidence
        reason = f"{type(exc).__name__}: {exc}"
        plan, validation, result, bundle = _capability_synthetic_failure(
            request,
            provider_name=provider_name,
            phase="support",
            reason=reason,
        )
        return provider, plan, validation, result, None, persist(plan, validation, result, bundle)
    if not supported:
        reason = (
            f"Provider '{provider_name}' does not support capability "
            f"'{request.capability}:{request.action}'"
        )
        plan, validation, result, bundle = _capability_synthetic_failure(
            request,
            provider_name=provider_name,
            phase="support",
            reason=reason,
            status="unavailable",
        )
        return provider, plan, validation, result, None, persist(plan, validation, result, bundle)

    try:
        plan = provider.plan(request, context=context)
    except Exception as exc:  # noqa: BLE001 - provider boundary must be represented as evidence
        reason = f"{type(exc).__name__}: {exc}"
        plan, validation, result, bundle = _capability_synthetic_failure(
            request,
            provider_name=provider_name,
            phase="plan",
            reason=reason,
        )
        return provider, plan, validation, result, None, persist(plan, validation, result, bundle)

    try:
        validation = provider.validate(plan, context=context)
    except Exception as exc:  # noqa: BLE001 - provider boundary must be represented as evidence
        reason = f"{type(exc).__name__}: {exc}"
        plan, validation, result, bundle = _capability_synthetic_failure(
            request,
            provider_name=provider_name,
            phase="validate",
            reason=reason,
            plan=plan,
        )
        return provider, plan, validation, result, None, persist(plan, validation, result, bundle)
    if not getattr(validation, "ok", False):
        reason = ", ".join(getattr(validation, "errors", []) or []) or "validation failed"
        plan, validation, result, bundle = _capability_synthetic_failure(
            request,
            provider_name=provider_name,
            phase="validate",
            reason=reason,
            plan=plan,
            validation=validation,
        )
        return provider, plan, validation, result, None, persist(plan, validation, result, bundle)

    try:
        result = provider.execute(plan, context=context)
    except Exception as exc:  # noqa: BLE001 - provider boundary must be represented as evidence
        reason = f"{type(exc).__name__}: {exc}"
        plan, validation, result, bundle = _capability_synthetic_failure(
            request,
            provider_name=provider_name,
            phase="execute",
            reason=reason,
            plan=plan,
            validation=validation,
        )
        return provider, plan, validation, result, None, persist(plan, validation, result, bundle)

    rollback_result = None
    if rollback:
        try:
            rollback_result = provider.rollback(result, context=context)
        except Exception as exc:  # noqa: BLE001 - preserve the execution result and report rollback failure
            if CapabilityRollbackResult is None:
                raise
            rollback_result = CapabilityRollbackResult(
                capability=str(request.capability),
                provider=provider_name,
                session_id=str(request.session_id),
                ok=False,
                restored=False,
                details={"reason": f"{type(exc).__name__}: {exc}", "phase": "rollback"},
            )
    try:
        bundle = provider.collect_artifacts(result, str(out_dir), context=context)
        artifact_paths = persist(plan, validation, result, bundle, rollback_result)
    except Exception as exc:  # noqa: BLE001 - evidence collection failures require their own audit trail
        reason = f"{type(exc).__name__}: {exc}"
        plan, validation, result, bundle = _capability_synthetic_failure(
            request,
            provider_name=provider_name,
            phase="collect_artifacts",
            reason=reason,
            plan=plan,
            validation=validation,
            prior_result=result,
        )
        artifact_paths = persist(plan, validation, result, bundle, rollback_result)
    return provider, plan, validation, result, rollback_result, artifact_paths


def experiment_create_command(args: argparse.Namespace) -> int:
    context = _experiment_context(args)
    if context is None:
        return 3
    _, store = context
    metadata = {"label": args.label} if args.label else {}
    experiment = store.create(args.sample, options=_experiment_options(args), metadata=metadata)
    _print_json_payload(
        {
            "experiment": experiment,
            "analysis_command": store.build_analysis_command(experiment["id"]),
        }
    )
    return 0


def experiment_list_command(args: argparse.Namespace) -> int:
    context = _experiment_context(args)
    if context is None:
        return 3
    _, store = context
    try:
        experiments = store.list(limit=args.limit)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Experiment list failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        _print_json_payload({"experiments": experiments, "count": len(experiments)})
    else:
        for experiment in experiments:
            print(f"{experiment.get('id')}  {experiment.get('status')}  {experiment.get('sample')}")
    return 0


def experiment_show_command(args: argparse.Namespace) -> int:
    context = _experiment_context(args)
    if context is None:
        return 3
    _, store = context
    try:
        experiment = store.get(args.experiment_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Experiment not available: {args.experiment_id}: {exc}", file=sys.stderr)
        return 2
    _print_json_payload({"experiment": experiment, "analysis_command": store.build_analysis_command(args.experiment_id)})
    return 0


def _plan_experiment(store: Any, experiment_id: str) -> Dict[str, Any]:
    experiment = store.get(experiment_id)
    if experiment.get("status") == "queued":
        experiment = store.set_status(experiment_id, "planned", detail="analysis_command_planned")
    return experiment


def experiment_plan_command(args: argparse.Namespace) -> int:
    context = _experiment_context(args)
    if context is None:
        return 3
    _, store = context
    try:
        experiment = _plan_experiment(store, args.experiment_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Experiment plan failed: {args.experiment_id}: {exc}", file=sys.stderr)
        return 2
    _print_json_payload({"experiment": experiment, "analysis_command": store.build_analysis_command(args.experiment_id)})
    return 0


def experiment_run_command(args: argparse.Namespace) -> int:
    """Run an explicit local adapter or emit a deterministic no-execution plan."""

    context = _experiment_context(args)
    if context is None:
        return 3
    config, store = context
    if not args.dry_run and args.timeout <= 0:
        print("Experiment timeout must be positive for --execute-local.", file=sys.stderr)
        return 2
    try:
        experiment = _plan_experiment(store, args.experiment_id)
        command = store.build_analysis_command(args.experiment_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Experiment run failed: {args.experiment_id}: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        _print_json_payload({"experiment": experiment, "analysis_command": command, "executed": False})
        return 0

    if experiment.get("status") != "planned":
        print(f"Experiment must be planned before local execution: {args.experiment_id}", file=sys.stderr)
        return 2

    store.set_status(args.experiment_id, "running", detail="local_runner_started")
    try:
        completed = subprocess.run(
            command,
            cwd=str(Path(__file__).resolve().parents[1]),
            env=_local_runner_environment(config.workspace),
            capture_output=True,
            text=True,
            timeout=args.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        result = store.record_result(
            args.experiment_id,
            status="failed",
            summary={"runner": "local", "timeout_seconds": args.timeout},
            error=f"local runner timed out: {exc}",
        )
        _print_json_payload({"experiment": result, "analysis_command": command, "executed": True, "timeout": True})
        return 124
    except (OSError, ValueError) as exc:
        result = store.record_result(
            args.experiment_id,
            status="failed",
            summary={"runner": "local"},
            error=f"local runner unavailable: {exc}",
        )
        _print_json_payload({"experiment": result, "analysis_command": command, "executed": True})
        return 2

    try:
        analysis_result = json.loads(completed.stdout) if completed.stdout.strip() else {}
    except json.JSONDecodeError:
        analysis_result = {}
    artifacts = analysis_result.get("artifacts") if isinstance(analysis_result, Mapping) else []
    summary = {
        "runner": "local",
        "returncode": completed.returncode,
        "session_id": analysis_result.get("session_id") if isinstance(analysis_result, Mapping) else None,
        "out_dir": analysis_result.get("out_dir") if isinstance(analysis_result, Mapping) else None,
    }
    status = "completed" if completed.returncode == 0 else "failed"
    error = completed.stderr.strip()[:2000] if completed.returncode else None
    result = store.record_result(
        args.experiment_id,
        status=status,
        artifacts=artifacts if isinstance(artifacts, list) else [],
        summary=summary,
        error=error,
    )
    _print_json_payload(
        {
            "experiment": result,
            "analysis_command": command,
            "executed": True,
            "returncode": completed.returncode,
        }
    )
    return int(completed.returncode)


def dashboard_command(args: argparse.Namespace) -> int:
    if build_dashboard is None or serve_dashboard is None:
        print("Dashboard runtime is unavailable because dashboard modules could not be imported.", file=sys.stderr)
        return 3
    config = load_config(args.workspace)
    destination = Path(args.out) if args.out else config.workspace / "dashboard"
    data = build_dashboard(config.workspace, out_dir=destination, knowledge_dir=config.knowledge_dir)
    payload: Dict[str, Any] = {
        "dashboard_dir": str(destination),
        "index": str(destination / "index.html"),
        "data": str(destination / "data.json"),
        "summary": data.get("summary") or {},
        "source_reconstruction": ((data.get("source_reconstruction") or {}).get("summary") or {}),
    }
    if not args.serve:
        _print_json_payload(payload)
        return 0

    port = args.port if args.port is not None else config.dashboard_port
    server = serve_dashboard(destination, host=args.host, port=port)
    host, actual_port = server.server_address[:2]
    payload["url"] = f"http://{host}:{actual_port}/"
    _print_json_payload(payload)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.shutdown()
        server.server_close()
    return 0


def web_command(args: argparse.Namespace) -> int:
    config = load_config(args.workspace)
    workspace = config.workspace
    frontend = Path(args.frontend_dir).resolve() if args.frontend_dir else workspace / "frontend" / "dist"
    configured = os.environ.get("REVERSE_ANALYZER_GO_SERVER")
    candidates = [
        Path(configured).expanduser() if configured else None,
        workspace / "build" / ("reverse-analyzer-server.exe" if os.name == "nt" else "reverse-analyzer-server"),
    ]
    binary = next((candidate for candidate in candidates if candidate and candidate.is_file()), None)
    if binary is not None:
        command = [str(binary)]
    elif installed := shutil.which("reverse-analyzer-server"):
        command = [installed]
    elif go := shutil.which("go"):
        command = [go, "run", "./cmd/reverse-analyzer-server"]
    else:
        print("Go control-plane binary is unavailable; build ./cmd/reverse-analyzer-server or set REVERSE_ANALYZER_GO_SERVER.", file=sys.stderr)
        return 3
    if not frontend.is_dir():
        print(f"Frontend build not found: {frontend}. Run npm run build --prefix frontend.", file=sys.stderr)
        return 3
    process_env = os.environ.copy()
    process_env.update(
        {
            "REVERSE_ANALYZER_WORKSPACE": str(workspace),
            "REVERSE_ANALYZER_FRONTEND_DIR": str(frontend),
            "REVERSE_ANALYZER_WEB_ADDR": f"{args.host}:{args.port}",
        }
    )
    _print_json_payload(
        {
            "url": f"http://{args.host}:{args.port}/",
            "workspace": str(workspace),
            "mode": "go-control-plane",
            "command": command,
            "execution_boundary": "Experiment creation is plan-only by default; local execution requires explicit Web confirmation.",
        }
    )
    process: subprocess.Popen[Any] | None = None
    try:
        process = subprocess.Popen(command, cwd=workspace, env=process_env)
        return int(process.wait())
    except OSError as exc:
        print(f"Unable to start Go control plane: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        if process is not None:
            process.terminate()
            process.wait(timeout=15)
        return 0


def knowledge_command(args: argparse.Namespace) -> int:
    if KnowledgeBase is None:
        print("Knowledge runtime is unavailable.", file=sys.stderr)
        return 3
    config = load_config(args.workspace)
    knowledge = KnowledgeBase(config.knowledge_dir)
    tags = [tag for value in (getattr(args, "tag", None) or []) for tag in value.split(",")]
    try:
        if args.knowledge_command == "add":
            content = Path(args.file).read_text(encoding="utf-8") if args.file else args.content
            metadata = json.loads(args.metadata) if args.metadata else {}
            if not isinstance(metadata, dict):
                raise ValueError("--metadata must decode to a JSON object")
            payload = knowledge.add_document(
                content,
                document_type=args.type,
                title=args.title,
                scope=args.scope,
                tags=tags,
                metadata=metadata,
            )
        elif args.knowledge_command == "list":
            documents = knowledge.list_documents(
                document_type=args.type,
                scope=args.scope,
                tags=tags,
                limit=args.limit,
            )
            payload = {"count": len(documents), "documents": documents}
        else:
            matches = knowledge.search_documents(
                args.query,
                document_type=args.type,
                scope=args.scope,
                tags=tags,
                limit=args.limit,
                min_score=args.min_score,
            )
            payload = {"query": args.query, "count": len(matches), "matches": matches}
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Knowledge operation failed: {exc}", file=sys.stderr)
        return 2
    _print_json_payload(payload)
    return 0


def skills_command(args: argparse.Namespace) -> int:
    if SkillCatalog is None:
        print("Skill catalog runtime is unavailable.", file=sys.stderr)
        return 3
    skills_root = Path(
        getattr(args, "skills_root", None) or Path(__file__).resolve().parents[1] / "reverse-skills"
    )
    if not skills_root.is_dir():
        print(
            f"Skill suite root not found: {skills_root}. Pass `skills --root <path>` for an external suite.",
            file=sys.stderr,
        )
        return 2
    catalog = SkillCatalog(skills_root)
    if args.skills_command == "audit":
        _print_json_payload(catalog.audit())
        return 0
    if args.skills_command == "route":
        try:
            _print_json_payload(
                catalog.route(
                    args.query,
                    target=args.target,
                    endpoint=args.endpoint,
                    interface=args.interface,
                    package=args.package,
                    limit=args.limit,
                )
            )
        except ValueError as exc:
            print(f"Skill routing failed: {exc}", file=sys.stderr)
            return 2
        return 0
    if args.skills_command == "show":
        record = catalog.get(args.skill_id)
        if record is None:
            print(f"Skill not found: {args.skill_id}", file=sys.stderr)
            return 2
        _print_json_payload(record.to_dict())
        return 0
    records = catalog.discover()
    if args.route:
        records = [record for record in records if args.route in record.routes]
    _print_json_payload({"count": len(records), "skills": [record.to_dict() for record in records]})
    return 0


def coverage_command(args: argparse.Namespace) -> int:
    if not callable(audit_capability_coverage):
        print("Capability coverage runtime is unavailable.", file=sys.stderr)
        return 3
    matrix = Path(__file__).resolve().parents[1] / "docs" / "skill_parity_matrix.md"
    payload = audit_capability_coverage(matrix)
    if args.only_unresolved:
        payload = {**payload, "capabilities": payload.pop("unresolved")}
    _print_json_payload(payload)
    return 0


def platform_command(args: argparse.Namespace) -> int:
    if not callable(build_platform_catalog):
        print("Platform catalog runtime is unavailable.", file=sys.stderr)
        return 3
    payload = build_platform_catalog(Path(__file__).resolve().parents[1])
    if args.platform_command == "audit":
        payload = {
            "summary": payload["summary"],
            "integration": payload.get("integration", {}),
            "execution_boundary": payload["execution_boundary"],
        }
    _print_json_payload(payload)
    return 0


def debugger_import_command(args: argparse.Namespace) -> int:
    try:
        from .tools.debugger_import import debugger_session_import
        payload = debugger_session_import(args.input, source=args.source, out=args.out)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Debugger import failed: {exc}", file=sys.stderr)
        return 2
    _print_json_payload(payload)
    return 0


def _add_experiment_analysis_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dynamic", action="store_true", help="Include optional dynamic tracing in the planned analysis command.")
    parser.add_argument("--dynamic-backend", choices=("frida", "procmon", "all"), default="frida")
    parser.add_argument("--dynamic-profile", choices=("auto", "behavior", "quick", "unpacking", "network", "persistence"), default="auto")
    parser.add_argument("--dynamic-duration", type=float, default=10.0)
    parser.add_argument("--memory-analysis", action="store_true", help="Include read-only runtime memory evidence when an existing PID is supplied.")
    parser.add_argument("--memory-plan", default=None, help="Optional JSON plan containing offline memory snapshot diff and address mapping inputs.")
    parser.add_argument("--gui", action="store_true", help="Include GUI fingerprinting and strategy selection.")
    parser.add_argument("--gui-runtime", action="store_true", help="Include optional runtime UI probing.")
    parser.add_argument("--gui-visual", action="store_true", help="Include GUI visual parsing.")
    parser.add_argument("--reconstruct", action="store_true", help="Include native reconstruction output.")
    parser.add_argument("--reconstruct-gui", action="store_true", help="Include GUI reconstruction output.")
    parser.add_argument("--gui-target", default="auto")
    parser.add_argument("--gui-interaction-trace", default=None)


def _add_capability_alias_options(
    parser: argparse.ArgumentParser,
    *,
    target: str,
    rollback: bool = True,
) -> None:
    if target == "process":
        parser.add_argument("--pid", type=int, required=True, help="Target process ID.")
        parser.set_defaults(sample=None)
    elif target == "sample":
        parser.add_argument("sample", help="Target file or unpacked project directory.")
        parser.set_defaults(pid=None)
    else:
        raise ValueError(f"unsupported capability alias target: {target}")
    parser.add_argument("--out", required=True, help="Output root for session, audit, report, and evidence artifacts.")
    parser.add_argument("--provider", default=None, help="Optional provider override.")
    parser.add_argument("--param", action="append", default=None, help="Additional provider parameter in key=value form.")
    if rollback:
        parser.add_argument("--rollback", action="store_true", help="Execute the generated rollback plan after the operation.")
    else:
        parser.set_defaults(rollback=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reverse_analyzer",
        description="PE-style reverse analysis CLI scaffold.",
    )
    parser.add_argument("--install-guide", metavar="TOOL", help="Print setup instructions for an optional tool, e.g. ghidra, frida, or procmon.")
    subparsers = parser.add_subparsers(dest="command", required=False)

    analyze = subparsers.add_parser("analyze", help="Run an analysis session for a sample.")
    analyze.add_argument("sample", help="Path to the binary/sample to analyze.")
    analyze.add_argument("--out", required=True, help="Output directory for session artifacts and reports.")
    analyze.add_argument("--max-iterations", type=int, default=8, help="Maximum AgentLoop iterations.")
    analyze.add_argument("--dynamic", action="store_true", help="Run optional dynamic tracing with Frida when configured.")
    analyze.add_argument("--dynamic-backend", choices=("frida", "procmon", "all"), default="frida", help="Dynamic backend to run when --dynamic is set.")
    analyze.add_argument("--dynamic-profile", choices=("auto", "behavior", "quick", "unpacking", "network", "persistence"), default="auto", help="Built-in Frida hook profile used when --dynamic-hook-file is not provided; auto chooses from static signals.")
    analyze.add_argument("--dynamic-duration", type=float, default=10.0, help="Frida tracing duration in seconds.")
    analyze.add_argument("--dynamic-arg", action="append", default=None, help="Argument passed to the dynamically spawned target. Repeatable.")
    analyze.add_argument("--attach-pid", type=int, default=None, help="Attach Frida to an existing PID instead of spawning the sample.")
    analyze.add_argument("--memory-analysis", action="store_true", help="Collect bounded read-only memory evidence; snapshots require an explicit --attach-pid.")
    analyze.add_argument("--memory-plan", default=None, help="JSON plan for offline memory snapshot diffs and address mappings.")
    analyze.add_argument("--dynamic-hook-file", default=None, help="JSON hook plan for Frida; defaults to the built-in Windows reverse-analysis hooks.")
    analyze.add_argument("--procmon-path", default=None, help="Path to Procmon64.exe/Procmon.exe for --dynamic-backend procmon/all.")
    analyze.add_argument("--decompile", action="store_true", help="Run Ghidra Headless decompilation when configured.")
    analyze.add_argument("--ghidra-home", default=None, help="Path to Ghidra root directory; overrides GHIDRA_HOME.")
    analyze.add_argument("--decompiler-timeout", type=int, default=900, help="Ghidra Headless timeout in seconds.")
    analyze.add_argument("--yara-rules", default=None, help="Optional YARA rule file or directory; defaults to rules/yara.")
    analyze.add_argument("--reconstruct", action="store_true", help="Generate a compilable reconstruction stub project in the output directory.")
    analyze.add_argument(
        "--runtime-validation-spec",
        default=None,
        help="Optional JSON specification for bounded runtime validation of a reconstructed source project.",
    )
    analyze.add_argument(
        "--behavior-validation-spec",
        default=None,
        help="Optional JSON specification for differential execution of the original and reconstructed projects.",
    )
    analyze.add_argument(
        "--behavior-original-dir",
        default=None,
        help="Original-project root for differential behavior validation; defaults to the sample directory.",
    )
    analyze.add_argument("--require-ios", action="store_true", help=argparse.SUPPRESS)
    analyze.add_argument("--gui", action="store_true", help="Run GUI technology fingerprinting, resource cataloging, and strategy selection.")
    analyze.add_argument("--gui-runtime", action="store_true", help="Attempt optional runtime UI tree probing for GUI reconstruction.")
    analyze.add_argument("--gui-visual", action="store_true", help="Parse supplied GUI screenshots for visual reconstruction evidence.")
    analyze.add_argument("--reconstruct-gui", action="store_true", help="Generate a GUI reconstruction project using the selected GUI strategy.")
    analyze.add_argument("--gui-target", default="auto", help="GUI reconstruction target stack; auto preserves the detected original stack when possible.")
    analyze.add_argument("--gui-screenshot-dir", default=None, help="Directory of original GUI screenshots for visual parsing/regression.")
    analyze.add_argument("--gui-interaction-trace", default=None, help="Optional JSON interaction trace used to build a GUI state machine without executing extra UI actions.")
    analyze.add_argument("--adb-path", default=None, help="Optional adb executable used by --gui-runtime for Android APK accessibility dumps.")
    analyze.add_argument("--android-serial", default=None, help="Optional adb device serial used by --gui-runtime for Android APK probing.")
    analyze.set_defaults(func=analyze_command)

    experiment = subparsers.add_parser("experiment", help="Create, plan, and explicitly dispatch reproducible analysis experiments.")
    experiment_commands = experiment.add_subparsers(dest="experiment_command", required=True)

    experiment_create = experiment_commands.add_parser("create", help="Create a queued experiment without executing a sample.")
    experiment_create.add_argument("sample", help="Sample path recorded by the experiment.")
    experiment_create.add_argument("--workspace", default=None, help="Workspace root; defaults to current directory.")
    experiment_create.add_argument("--label", default=None, help="Optional human-readable experiment label.")
    _add_experiment_analysis_options(experiment_create)
    experiment_create.set_defaults(func=experiment_create_command)

    experiment_list = experiment_commands.add_parser("list", help="List persisted experiments.")
    experiment_list.add_argument("--workspace", default=None, help="Workspace root; defaults to current directory.")
    experiment_list.add_argument("--limit", type=int, default=None, help="Maximum records to return.")
    experiment_list.add_argument("--json", action="store_true", help="Emit JSON instead of text rows.")
    experiment_list.set_defaults(func=experiment_list_command)

    experiment_show = experiment_commands.add_parser("show", help="Show one experiment and its deterministic analysis command.")
    experiment_show.add_argument("experiment_id")
    experiment_show.add_argument("--workspace", default=None, help="Workspace root; defaults to current directory.")
    experiment_show.set_defaults(func=experiment_show_command)

    experiment_plan = experiment_commands.add_parser("plan", help="Mark a queued experiment planned and print its analysis command.")
    experiment_plan.add_argument("experiment_id")
    experiment_plan.add_argument("--workspace", default=None, help="Workspace root; defaults to current directory.")
    experiment_plan.set_defaults(func=experiment_plan_command)

    experiment_run = experiment_commands.add_parser("run", help="Emit a dry-run or explicitly dispatch the local analysis adapter.")
    experiment_run.add_argument("experiment_id")
    experiment_run.add_argument("--workspace", default=None, help="Workspace root; defaults to current directory.")
    experiment_run.add_argument("--timeout", type=float, default=900.0, help="Local runner timeout in seconds.")
    run_mode = experiment_run.add_mutually_exclusive_group(required=True)
    run_mode.add_argument("--dry-run", action="store_true", help="Plan only; never execute a sample.")
    run_mode.add_argument("--execute-local", action="store_true", help="Explicitly invoke the current host's analysis CLI; use an isolated workspace when dynamic tracing is enabled.")
    experiment_run.set_defaults(func=experiment_run_command)

    dashboard = subparsers.add_parser("dashboard", help="Build the offline reverse-engineering command deck, including reconstructed-source artifacts.")
    dashboard.add_argument("--workspace", default=None, help="Workspace root; defaults to current directory.")
    dashboard.add_argument("--out", default=None, help="Dashboard output directory; defaults to <workspace>/dashboard.")
    dashboard.add_argument("--serve", action="store_true", help="Serve the generated dashboard on the loopback host until interrupted.")
    dashboard.add_argument("--host", default="127.0.0.1", help="Dashboard server host when --serve is used.")
    dashboard.add_argument("--port", type=int, default=None, help="Dashboard server port; defaults to configuration or 8088.")
    dashboard.set_defaults(func=dashboard_command)

    web = subparsers.add_parser(
        "web",
        help="Serve the React Web console and loopback workspace API.",
    )
    web.add_argument("--workspace", default=None, help="Workspace root; defaults to current directory.")
    web.add_argument(
        "--frontend-dir",
        default=None,
        help="Built frontend directory; defaults to frontend/dist.",
    )
    web.add_argument("--host", default="127.0.0.1", help="Web console bind host.")
    web.add_argument("--port", type=int, default=8090, help="Web console port.")
    web.set_defaults(func=web_command)

    knowledge = subparsers.add_parser("knowledge", help="Store and retrieve reusable typed analysis knowledge.")
    knowledge_commands = knowledge.add_subparsers(dest="knowledge_command", required=True)

    knowledge_add = knowledge_commands.add_parser("add", help="Store a reusable guide, answer, code sample, or memory.")
    content_source = knowledge_add.add_mutually_exclusive_group(required=True)
    content_source.add_argument("--content", help="Knowledge document content.")
    content_source.add_argument("--file", help="UTF-8 file containing the knowledge document.")
    knowledge_add.add_argument("--type", choices=("memory", "guide", "answer", "code"), default="memory")
    knowledge_add.add_argument("--title", default=None)
    knowledge_add.add_argument("--scope", default="global", help="Logical engagement or project scope.")
    knowledge_add.add_argument("--tag", action="append", default=None, help="Tag or comma-separated tags; repeatable.")
    knowledge_add.add_argument("--metadata", default=None, help="JSON object with source-specific metadata.")
    knowledge_add.add_argument("--workspace", default=None)
    knowledge_add.set_defaults(func=knowledge_command)

    for command_name in ("list", "search"):
        command = knowledge_commands.add_parser(command_name, help=f"{command_name.title()} reusable knowledge documents.")
        if command_name == "search":
            command.add_argument("query")
            command.add_argument("--min-score", type=float, default=0.0)
        command.add_argument("--type", choices=("memory", "guide", "answer", "code"), default=None)
        command.add_argument("--scope", default=None)
        command.add_argument("--tag", action="append", default=None)
        command.add_argument("--limit", type=int, default=5 if command_name == "search" else None)
        command.add_argument("--workspace", default=None)
        command.set_defaults(func=knowledge_command)

    skills = subparsers.add_parser("skills", help="Discover, route, and audit repository-backed skill instructions.")
    skills.add_argument(
        "--root",
        dest="skills_root",
        type=Path,
        default=None,
        help="External skill-suite root; use when the installed CLI has no source-adjacent assets.",
    )
    skills_commands = skills.add_subparsers(dest="skills_command", required=True)
    skills_list = skills_commands.add_parser("list", help="List all discovered skill instructions.")
    skills_list.add_argument("--route", choices=("pe", "android", "ios", "protocol", "source", "memory", "patch", "jailbreak", "capability"), default=None)
    skills_list.set_defaults(func=skills_command)
    skills_show = skills_commands.add_parser("show", help="Show one discovered skill and its platform routes.")
    skills_show.add_argument("skill_id")
    skills_show.set_defaults(func=skills_command)
    skills_audit = skills_commands.add_parser("audit", help="Audit metadata and platform routing coverage for all skills.")
    skills_audit.set_defaults(func=skills_command)
    skills_route = skills_commands.add_parser("route", help="Plan a master-first reverse workflow without executing a target.")
    skills_route.add_argument("query", help="Natural-language request to route.")
    skills_route.add_argument("--target", default=None, help="Optional local target path used only for suffix routing.")
    skills_route.add_argument(
        "--endpoint",
        "--url",
        dest="endpoint",
        default=None,
        help="Optional HTTP(S) endpoint descriptor; it is classified but never fetched.",
    )
    skills_route.add_argument("--interface", default=None, help="Optional interface kind such as rest, graphql, or websocket.")
    skills_route.add_argument("--package", default=None, help="Optional package ecosystem such as android, dotnet, or npm.")
    skills_route.add_argument("--limit", type=int, default=3, help="Maximum ranked skill routes to return.")
    skills_route.set_defaults(func=skills_command)

    coverage = subparsers.add_parser("coverage", help="Audit executable capability parity and remaining acceptance gates.")
    coverage.add_argument("--only-unresolved", action="store_true", help="Return unresolved capabilities as the primary capability list.")
    coverage.set_defaults(func=coverage_command)

    platform = subparsers.add_parser("platform", help="Inspect the unified read-only platform asset catalog.")
    platform_commands = platform.add_subparsers(dest="platform_command", required=True)
    platform_catalog = platform_commands.add_parser("catalog", help="List skills, tools, providers, scripts, and external dependency manifests.")
    platform_catalog.set_defaults(func=platform_command)
    platform_audit = platform_commands.add_parser("audit", help="Report platform integration coverage without claiming live acceptance.")
    platform_audit.set_defaults(func=platform_command)

    debugger_import = subparsers.add_parser("debugger-import", help="Import x64dbg, WinDbg, IDA, or minidump evidence without executing a target.")
    debugger_import.add_argument("input")
    debugger_import.add_argument("--source", choices=("auto", "x64dbg", "windbg", "ida", "minidump"), default="auto")
    debugger_import.add_argument("--out", default=None, help="Optional normalized diagnostic JSON artifact.")
    debugger_import.set_defaults(func=debugger_import_command)

    jailbreak = subparsers.add_parser(
        "jailbreak",
        help="Run the standalone active model-jailbreak engine through the platform audit pipeline.",
    )
    jailbreak_commands = jailbreak.add_subparsers(
        dest="jailbreak_command",
        required=True,
    )

    jailbreak_run = jailbreak_commands.add_parser(
        "run",
        help="Generate, mutate, and execute an adaptive jailbreak campaign.",
    )
    jailbreak_run.add_argument("campaign", help="Campaign JSON file.")
    jailbreak_run.add_argument(
        "--out",
        required=True,
        help="Output root for campaign, audit, report, evidence, and dashboard artifacts.",
    )
    jailbreak_run.add_argument("--base-url", default=None, help="OpenAI-compatible API base URL override.")
    jailbreak_run.add_argument("--model", default=None, help="Target model override, including any GPT-family model identifier.")
    jailbreak_run.add_argument(
        "--api-key-env",
        default=None,
        help="Environment variable containing the API key; the key value is never persisted.",
    )
    jailbreak_run.add_argument("--timeout", type=float, default=None, help="Per-request timeout in seconds.")
    jailbreak_run.add_argument("--max-attempts", type=int, default=None, help="Maximum remote attempts.")
    jailbreak_run.add_argument("--max-rounds", type=int, default=None, help="Maximum adaptive rounds.")
    jailbreak_run.add_argument(
        "--strategy",
        action="append",
        dest="strategies",
        default=None,
        help="Built-in jailbreak strategy override; repeat to define the strategy set.",
    )
    jailbreak_run.add_argument(
        "--attack-mode",
        action="append",
        dest="attack_modes",
        metavar="MODE",
        help="Attack algorithm; repeat the option or provide a comma-separated list.",
    )
    jailbreak_run.add_argument(
        "--semantic-judge",
        choices=("disabled", "heuristic", "model"),
        default=None,
        help="Semantic success judge override.",
    )
    jailbreak_run.add_argument(
        "--judge-model",
        default=None,
        help="Model used by the model-backed semantic judge.",
    )
    jailbreak_run.add_argument(
        "--instruction-profile",
        default=None,
        metavar="PROFILE",
        help="Named instruction bundle from the repository asset registry.",
    )
    jailbreak_run.add_argument(
        "--instruction-file",
        "--instruction-files",
        action="append",
        dest="instruction_files",
        default=None,
        metavar="PATH",
        help="Additional Markdown instruction asset; repeat for an ordered bundle.",
    )
    jailbreak_run.add_argument("--temperature", type=float, default=None)
    jailbreak_run.add_argument("--max-tokens", type=int, default=None)
    jailbreak_run.add_argument("--max-retries", type=int, default=None)
    jailbreak_run.add_argument("--retry-backoff-seconds", type=float, default=None)
    jailbreak_run.add_argument("--requests-per-minute", type=float, default=None)
    jailbreak_run.add_argument(
        "--extra-body",
        default=None,
        help="Additional OpenAI-compatible request body fields encoded as a JSON object.",
    )
    jailbreak_run.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        help=(
            "Stable checkpoint path; defaults to "
            "<out>/llm_jailbreak/checkpoints/<campaign-fingerprint>.json."
        ),
    )
    jailbreak_run.add_argument("--resume", action="store_true", help="Resume the campaign checkpoint when present.")
    jailbreak_run.add_argument(
        "--require-success",
        action="store_true",
        help="Return exit code 3 when no attempt is classified as a successful breakthrough.",
    )
    jailbreak_run.add_argument(
        "--provider",
        default="openai_compatible_jailbreak",
        help="Capability provider override.",
    )
    jailbreak_run.set_defaults(func=jailbreak_run_command)

    jailbreak_validate = jailbreak_commands.add_parser(
        "validate",
        help="Validate and normalize a campaign without contacting a model.",
    )
    jailbreak_validate.add_argument("campaign", help="Campaign JSON file.")
    jailbreak_validate.add_argument("--json", action="store_true", help="Emit the normalized campaign as JSON.")
    jailbreak_validate.set_defaults(func=jailbreak_validate_command)

    jailbreak_strategies = jailbreak_commands.add_parser(
        "strategies",
        help="List the built-in active jailbreak strategies.",
    )
    jailbreak_strategies.add_argument("--json", action="store_true", help="Emit JSON.")
    jailbreak_strategies.set_defaults(func=jailbreak_strategies_command)

    jailbreak_profiles = jailbreak_commands.add_parser(
        "profiles",
        help="List repository-backed instruction profiles.",
    )
    jailbreak_profiles.add_argument("--json", action="store_true", help="Emit JSON.")
    jailbreak_profiles.set_defaults(func=jailbreak_profiles_command)

    jailbreak_doctor = jailbreak_commands.add_parser(
        "doctor",
        help="Probe endpoint authentication, model, chat schema, streaming, timeout, and rate-limit signals.",
    )
    jailbreak_doctor.add_argument("--base-url", required=True)
    jailbreak_doctor.add_argument("--model", required=True)
    jailbreak_doctor.add_argument("--api-key-env", default="OPENAI_API_KEY")
    jailbreak_doctor.add_argument("--timeout", type=float, default=30.0)
    jailbreak_doctor.add_argument("--json", action="store_true", help="Emit JSON.")
    jailbreak_doctor.set_defaults(func=jailbreak_doctor_command)

    jailbreak_promote = jailbreak_commands.add_parser(
        "promote",
        help="Verify retained HTTP campaign evidence and write promotion.json.",
    )
    jailbreak_promote.add_argument("path", type=Path, help="Standalone output or platform output root.")
    jailbreak_promote.add_argument(
        "--secret-env",
        action="append",
        default=[],
        help="Environment variable whose value must not appear in retained artifacts; repeatable.",
    )
    jailbreak_promote.add_argument("--json", action="store_true", help="Emit JSON.")
    jailbreak_promote.set_defaults(func=jailbreak_promote_command)

    capability = subparsers.add_parser("capability", help="Run registry-backed capability providers with audit/report artifacts.")
    capability_commands = capability.add_subparsers(dest="capability_command", required=True)

    capability_run = capability_commands.add_parser("run", help="Execute a registered capability provider and persist audit artifacts.")
    capability_run.add_argument(
        "--capability",
        required=True,
        help="Capability name from `capability list`; provider availability is validated by the registry at runtime.",
    )
    capability_run.add_argument("--action", required=True, help="Capability action passed to the provider, e.g. scan or plan.")
    capability_run.add_argument("--sample", default=None, help="Optional sample/file target.")
    capability_run.add_argument("--pid", type=int, default=None, help="Optional process target PID.")
    capability_run.add_argument("--out", required=True, help="Output directory for capability audit/report artifacts.")
    capability_run.add_argument("--provider", default=None, help="Preferred provider name when multiple providers are registered.")
    capability_run.add_argument("--param", action="append", default=None, help="Capability parameter in key=value form. Repeatable.")
    capability_run.add_argument("--rollback", action="store_true", help="Request provider rollback after execution to validate reversibility.")
    capability_run.set_defaults(func=capability_run_command)

    capability_list = capability_commands.add_parser("list", help="List registered capabilities and their providers.")
    capability_list.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    capability_list.set_defaults(func=list_capabilities_command)

    capability_show_audit = capability_commands.add_parser("show-audit", help="Print the capability_audit section from a report.json file.")
    capability_show_audit.add_argument("--report", required=True, help="Path to report.json generated by capability run or analyze.")
    capability_show_audit.set_defaults(func=show_capability_audit_command)

    memory = subparsers.add_parser("memory", help="Run audited process-memory, injection, and hook capabilities.")
    memory_commands = memory.add_subparsers(dest="memory_command", required=True)

    memory_scan = memory_commands.add_parser("scan", help="Scan a process using a bounded AOB, text, or pointer pattern.")
    _add_capability_alias_options(memory_scan, target="process", rollback=False)
    memory_scan.add_argument("--pattern", default=None)
    memory_scan.add_argument("--pattern-type", choices=("aob", "ascii", "utf16", "pointer"), default="aob")
    memory_scan.add_argument(
        "--pointer-size",
        type=int,
        choices=(4, 8),
        default=8,
        help="Pointer width used when --pattern-type pointer is selected.",
    )
    memory_scan.add_argument("--start-address", default=None)
    memory_scan.add_argument("--end-address", default=None)
    memory_scan.add_argument("--max-results", type=int, default=256)
    memory_scan.set_defaults(
        func=_dedicated_capability_command,
        capability="memory_runtime",
        action="scan",
        capability_param_fields=(
            ("pattern", "pattern"),
            ("pattern_type", "pattern_type"),
            ("start_address", "start_address"),
            ("end_address", "end_address"),
            ("max_results", "max_results"),
        ),
    )

    memory_read = memory_commands.add_parser("read", help="Read a bounded process-memory range and persist evidence.")
    _add_capability_alias_options(memory_read, target="process", rollback=False)
    memory_read.add_argument("--address", required=True)
    memory_read.add_argument("--size", type=int, required=True)
    memory_read.set_defaults(
        func=_dedicated_capability_command,
        capability="memory_runtime",
        action="read",
        capability_param_fields=(("address", "address"), ("size", "size")),
    )

    memory_write = memory_commands.add_parser("write", help="Apply a precondition-bound memory write with rollback metadata.")
    _add_capability_alias_options(memory_write, target="process")
    memory_write.add_argument("--address", required=True)
    memory_write.add_argument("--data", required=True, help="Replacement bytes or text payload.")
    memory_write.add_argument("--encoding", choices=("hex", "ascii", "utf8", "utf16le"), default="hex")
    memory_write.add_argument("--expected", default=None, help="Expected original bytes encoded as hexadecimal.")
    memory_write.set_defaults(
        func=_dedicated_capability_command,
        capability="memory_runtime",
        action="write",
        capability_param_fields=(
            ("address", "address"),
            ("data", "data"),
            ("encoding", "encoding"),
            ("expected", "expected"),
        ),
    )

    memory_protect = memory_commands.add_parser("protect", help="Change page protection through an audited reversible plan.")
    _add_capability_alias_options(memory_protect, target="process")
    memory_protect.add_argument("--address", required=True)
    memory_protect.add_argument("--size", type=int, required=True)
    memory_protect.add_argument("--protection", required=True)
    memory_protect.add_argument("--expected-protection", default=None)
    memory_protect.set_defaults(
        func=_dedicated_capability_command,
        capability="memory_runtime",
        action="protect",
        capability_param_fields=(
            ("address", "address"),
            ("size", "size"),
            ("protection", "protection"),
            ("expected_protection", "expected_protection"),
        ),
    )

    memory_alloc = memory_commands.add_parser("alloc", help="Allocate remote memory and record a matching free rollback.")
    _add_capability_alias_options(memory_alloc, target="process")
    memory_alloc.add_argument("--size", type=int, required=True)
    memory_alloc.add_argument("--protection", default="rw")
    memory_alloc.set_defaults(
        func=_dedicated_capability_command,
        capability="memory_runtime",
        action="alloc",
        capability_param_fields=(("size", "size"), ("protection", "protection")),
    )

    memory_free = memory_commands.add_parser("free", help="Free a remote allocation after identity and range validation.")
    _add_capability_alias_options(memory_free, target="process")
    memory_free.add_argument("--address", required=True)
    memory_free.add_argument("--size", type=int, default=0)
    memory_free.set_defaults(
        func=_dedicated_capability_command,
        capability="memory_runtime",
        action="free",
        capability_param_fields=(("address", "address"), ("size", "size")),
    )

    memory_inject = memory_commands.add_parser("inject", help="Plan and execute a controlled DLL injection provider.")
    _add_capability_alias_options(memory_inject, target="process")
    memory_inject.add_argument("--dll", required=True, help="Absolute path to the DLL payload.")
    memory_inject.add_argument("--method", choices=("load_library", "manual_map"), default="load_library")
    memory_inject.add_argument("--timeout-ms", type=int, default=10000)
    memory_inject.add_argument("--expected-sha256", default=None)
    memory_inject.set_defaults(
        func=_dedicated_capability_command,
        capability="injector",
        action="inject",
        capability_param_fields=(
            ("dll", "dll_path"),
            ("method", "method"),
            ("timeout_ms", "timeout_ms"),
            ("expected_sha256", "expected_sha256"),
        ),
    )

    memory_hook = memory_commands.add_parser("hook-trace", help="Install an audited hook plan and collect a bounded trace.")
    _add_capability_alias_options(memory_hook, target="process")
    memory_hook.add_argument("--plan", required=True, help="Hook plan JSON path.")
    memory_hook.add_argument("--duration", type=float, default=10.0)
    memory_hook.add_argument("--backend", choices=("auto", "frida", "win32"), default="auto")
    memory_hook.set_defaults(
        func=_hook_capability_command,
        capability="hook_runtime",
        action="hook-trace",
    )

    engine = subparsers.add_parser("engine", help="Analyze Unity and Unreal engine samples.")
    engine_commands = engine.add_subparsers(dest="engine_command", required=True)
    engine_analyze = engine_commands.add_parser(
        "analyze",
        help="Run the complete static evidence pipeline with engine analysis.",
    )
    engine_analyze.add_argument("sample")
    engine_analyze.add_argument("--out", required=True)
    engine_analyze.set_defaults(func=_analysis_alias_command, analysis_options=())

    android = subparsers.add_parser("android", help="Analyze, unpack, rebuild, and verify Android application packages.")
    android_commands = android.add_subparsers(dest="android_command", required=True)
    android_analyze = android_commands.add_parser("analyze", help="Run the complete static evidence pipeline for an APK.")
    android_analyze.add_argument("sample")
    android_analyze.add_argument("--out", required=True)
    android_analyze.set_defaults(func=_analysis_alias_command, analysis_options=())

    android_decompile = android_commands.add_parser(
        "decompile",
        help="Decompile Java/Kotlin sources through the existing bounded JADX tool.",
    )
    android_decompile.add_argument("sample")
    android_decompile.add_argument("--out", required=True)
    android_decompile.add_argument("--destination", default="jadx")
    android_decompile.add_argument("--jadx", default=None)
    android_decompile.add_argument("--timeout", type=float, default=300.0)
    android_decompile.add_argument("--threads", type=int, default=2)
    android_decompile.set_defaults(func=android_decompile_command)

    ios = subparsers.add_parser("ios", help="Analyze iOS IPA application packages without executing or extracting them.")
    ios_commands = ios.add_subparsers(dest="ios_command", required=True)
    ios_analyze = ios_commands.add_parser("analyze", help="Run bounded static evidence analysis for an IPA.")
    ios_analyze.add_argument("sample")
    ios_analyze.add_argument("--out", required=True)
    ios_analyze.set_defaults(
        func=_analysis_alias_command,
        analysis_options=("require-ios",),
        require_ios=True,
    )

    android_unpack = android_commands.add_parser("unpack", help="Unpack an APK through the audited rebuild provider.")
    _add_capability_alias_options(android_unpack, target="sample", rollback=False)
    android_unpack.add_argument("--destination", default=None)
    android_unpack.add_argument("--strategy", choices=("zip_copy", "apktool_rebuild"), default=None)
    android_unpack.add_argument("--apktool", default=None)
    android_unpack.set_defaults(
        func=_dedicated_capability_command,
        capability="android_rebuild",
        action="unpack",
        capability_param_fields=(("destination", "unpack_dir"), ("strategy", "strategy"), ("apktool", "apktool_path")),
    )

    android_rebuild = android_commands.add_parser("rebuild", help="Rebuild an APK or decoded Android project into a new APK.")
    _add_capability_alias_options(android_rebuild, target="sample")
    android_rebuild.add_argument("--apk-out", default=None)
    android_rebuild.add_argument("--project-dir", default=None)
    android_rebuild.add_argument("--strategy", choices=("zip_copy", "apktool_rebuild"), default=None)
    android_rebuild.add_argument("--apktool", default=None)
    android_rebuild.add_argument("--apksigner", default=None)
    android_rebuild.add_argument("--keystore", default=None)
    android_rebuild.add_argument("--key-alias", default=None)
    android_rebuild.set_defaults(
        func=_dedicated_capability_command,
        capability="android_rebuild",
        action="rebuild",
        capability_param_fields=(
            ("apk_out", "out_path"),
            ("project_dir", "project_dir"),
            ("strategy", "strategy"),
            ("apktool", "apktool_path"),
            ("apksigner", "apksigner_path"),
            ("keystore", "keystore"),
            ("key_alias", "key_alias"),
        ),
    )

    android_verify = android_commands.add_parser("verify", help="Verify APK ZIP structure and optional signing metadata.")
    _add_capability_alias_options(android_verify, target="sample", rollback=False)
    android_verify.add_argument("--apksigner", default=None)
    android_verify.set_defaults(
        func=_dedicated_capability_command,
        capability="android_rebuild",
        action="verify",
        capability_param_fields=(("apksigner", "apksigner_path"),),
    )

    protocol = subparsers.add_parser(
        "protocol",
        help="Import bounded passive captures, infer message formats, and persist protocol evidence.",
    )
    protocol_commands = protocol.add_subparsers(dest="protocol_command", required=True)
    for command_name, command_help in (
        ("capture", "Import a passive capture and run the complete protocol evidence pipeline."),
        ("infer", "Infer framing and message formats through the complete protocol evidence pipeline."),
        ("summarize", "Summarize a passive source through the complete protocol evidence pipeline."),
    ):
        protocol_stage = protocol_commands.add_parser(command_name, help=command_help)
        protocol_stage.add_argument("source", help="PCAP, PCAPNG, JSON, JSONL, or raw passive evidence file.")
        protocol_stage.add_argument("--out", required=True, help="Output directory for report and protocol artifacts.")
        protocol_stage.add_argument(
            "--format",
            choices=("auto", "pcap", "pcapng", "json", "jsonl", "raw"),
            default="auto",
            help="Input format override; auto detects from content and suffix.",
        )
        protocol_stage.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024)
        protocol_stage.add_argument("--max-packets", type=int, default=4096)
        protocol_stage.add_argument("--max-messages", type=int, default=1024)
        protocol_stage.add_argument("--max-message-bytes", type=int, default=256 * 1024)
        protocol_stage.set_defaults(func=protocol_command)

    source = subparsers.add_parser("source", help="Generate provenance-backed source reconstruction projects.")
    source_commands = source.add_subparsers(dest="source_command", required=True)
    source_reconstruct = source_commands.add_parser("reconstruct", help="Run analysis and emit an editable reconstructed project skeleton.")
    source_reconstruct.add_argument("sample")
    source_reconstruct.add_argument("--out", required=True)
    source_reconstruct.add_argument("--strategy", choices=("auto",), default="auto")
    source_reconstruct.add_argument("--decompile", action="store_true")
    source_reconstruct.add_argument("--gui", action="store_true")
    source_reconstruct.add_argument(
        "--runtime-validation-spec",
        default=None,
        help="Optional JSON specification for bounded runtime validation of the generated project.",
    )
    source_reconstruct.add_argument(
        "--behavior-validation-spec",
        default=None,
        help="Optional JSON specification for original-versus-reconstruction behavior comparison.",
    )
    source_reconstruct.add_argument(
        "--behavior-original-dir",
        default=None,
        help="Original-project root for behavior comparison; defaults to the sample directory.",
    )
    source_reconstruct.set_defaults(
        func=_analysis_alias_command,
        analysis_options=("reconstruct", "decompile", "gui"),
        analysis_value_options=(
            "runtime-validation-spec",
            "behavior-validation-spec",
            "behavior-original-dir",
        ),
        reconstruct=True,
    )

    pe_patch = subparsers.add_parser("patch", help="Plan, verify, apply, and roll back PE-aware patch operations.")
    pe_patch_commands = pe_patch.add_subparsers(dest="pe_patch_command", required=True)

    pe_patch_plan = pe_patch_commands.add_parser("plan", help="Create verified PE patch artifacts from one explicit intent.")
    pe_patch_plan.add_argument("sample", help="Input PE file; it is read only and never modified in place.")
    pe_patch_plan.add_argument("--out", required=True, help="Session output root; artifacts are written beneath <out>/patch.")
    pe_patch_plan.add_argument(
        "--strategy",
        choices=(
            "auto",
            "inline_patch",
            "code_cave_patch",
            "section_extend_patch",
            "resource_replace",
            "iat_thunk_patch",
            "entrypoint_redirect",
            "overlay_preserve_patch",
        ),
        default="auto",
        help="Planning strategy; the current executable implementation is the verified inline strategy.",
    )
    pe_patch_selector = pe_patch_plan.add_mutually_exclusive_group()
    pe_patch_selector.add_argument("--offset", help="Explicit file offset, as decimal or 0x-prefixed integer.")
    pe_patch_selector.add_argument("--rva", help="Explicit PE RVA, as decimal or 0x-prefixed integer.")
    pe_patch_selector.add_argument("--aob", help="Explicit AOB pattern such as '74 05 ?? 90'.")
    pe_patch_plan.add_argument("--replacement", help="Equal-length replacement bytes encoded as hexadecimal.")
    pe_patch_plan.add_argument("--occurrence", default=0, help="Zero-based AOB occurrence, as decimal or 0x-prefixed integer.")
    pe_patch_plan.add_argument("--operation-id", default=None, help="Stable operation identifier recorded in audit artifacts.")
    pe_patch_plan.set_defaults(func=pe_patch_plan_command)

    pe_patch_verify = pe_patch_commands.add_parser("verify", help="Re-verify a PE patch plan without writing a binary.")
    pe_patch_verify.add_argument("sample", help="Input PE file used for hash, pre-image, layout, and CFG checks.")
    pe_patch_verify.add_argument("--plan", required=True, help="PE patch plan JSON to verify.")
    pe_patch_verify.add_argument("--out", default=None, help="Artifact directory; defaults to the plan directory.")
    pe_patch_verify.set_defaults(func=pe_patch_verify_command)

    pe_patch_apply = pe_patch_commands.add_parser("apply", help="Verify, then apply a PE patch plan to a new output copy.")
    pe_patch_apply.add_argument("sample", help="Input PE file; it is never modified in place.")
    pe_patch_apply.add_argument("--plan", required=True, help="PE patch plan JSON produced by patch plan.")
    pe_patch_apply.add_argument("--out", required=True, help="Patched output file; must differ from the input sample.")
    pe_patch_apply.add_argument("--artifact-dir", default=None, help="Artifact directory; defaults to the plan directory.")
    pe_patch_apply.set_defaults(func=pe_patch_apply_command)

    pe_patch_rollback = pe_patch_commands.add_parser("rollback", help="Restore a patched file to a separate output copy.")
    pe_patch_rollback.add_argument("patched", help="Patched PE file; it is never modified in place.")
    pe_patch_rollback.add_argument(
        "--plan",
        "--rollback",
        dest="rollback_plan",
        required=True,
        help="Rollback plan emitted by patch plan (normally rollback_plan.json).",
    )
    pe_patch_rollback.add_argument("--out", required=True, help="Restored output file; must differ from the patched file.")
    pe_patch_rollback.add_argument("--artifact-dir", default=None, help="Artifact directory; defaults to the rollback-plan directory.")
    pe_patch_rollback.set_defaults(func=pe_patch_rollback_command)

    android_elf_plan = pe_patch_commands.add_parser(
        "android-elf-plan",
        help="Create a verified layout-preserving ARM/AArch64 ELF patch plan.",
    )
    android_elf_plan.add_argument("sample", help="Input Android ELF shared object; it is never modified in place.")
    android_elf_plan.add_argument("--out", required=True, help="Session output root; artifacts are written beneath <out>/patch.")
    android_elf_selector = android_elf_plan.add_mutually_exclusive_group(required=True)
    android_elf_selector.add_argument("--virtual-address", help="Virtual address in a file-backed PT_LOAD segment.")
    android_elf_selector.add_argument("--file-offset", help="File offset in a file-backed PT_LOAD segment.")
    android_elf_plan.add_argument("--replacement", required=True, help="Equal-length replacement bytes encoded as hexadecimal.")
    android_elf_plan.add_argument(
        "--instruction-mode",
        choices=("auto", "arm", "thumb", "aarch64"),
        default="auto",
        help="Instruction-set validation mode.",
    )
    android_elf_plan.add_argument("--operation-id", default=None, help="Stable operation identifier recorded in audit artifacts.")
    android_elf_plan.set_defaults(func=android_elf_patch_plan_command)

    android_elf_verify = pe_patch_commands.add_parser(
        "android-elf-verify",
        help="Re-verify an Android ELF patch plan without writing a binary.",
    )
    android_elf_verify.add_argument("sample", help="Input Android ELF used for identity and pre-image checks.")
    android_elf_verify.add_argument("--plan", required=True, help="Android ELF patch plan JSON.")
    android_elf_verify.add_argument("--out", default=None, help="Artifact directory; defaults to the plan directory.")
    android_elf_verify.set_defaults(func=android_elf_patch_verify_command)

    android_elf_apply = pe_patch_commands.add_parser(
        "android-elf-apply",
        help="Verify and apply an Android ELF patch to a new output copy.",
    )
    android_elf_apply.add_argument("sample", help="Input Android ELF; it is never modified in place.")
    android_elf_apply.add_argument("--plan", required=True, help="Android ELF patch plan JSON.")
    android_elf_apply.add_argument("--out", required=True, help="Patched output file; must differ from the input sample.")
    android_elf_apply.add_argument("--artifact-dir", default=None, help="Artifact directory; defaults to the plan directory.")
    android_elf_apply.set_defaults(func=android_elf_patch_apply_command)

    android_elf_rollback = pe_patch_commands.add_parser(
        "android-elf-rollback",
        help="Restore a patched Android ELF to a separate output copy.",
    )
    android_elf_rollback.add_argument("patched", help="Patched Android ELF; it is never modified in place.")
    android_elf_rollback.add_argument(
        "--plan",
        "--rollback",
        dest="rollback_plan",
        required=True,
        help="Rollback plan emitted by android-elf-plan.",
    )
    android_elf_rollback.add_argument("--out", required=True, help="Restored output file; must differ from the patched file.")
    android_elf_rollback.add_argument("--artifact-dir", default=None, help="Artifact directory; defaults to the rollback-plan directory.")
    android_elf_rollback.set_defaults(func=android_elf_patch_rollback_command)

    dll_proxy = pe_patch_commands.add_parser(
        "dll-proxy",
        help="Generate a forwarding-DLL project from an explicit DLL copy.",
    )
    dll_proxy.add_argument("sample", help="Original DLL used only for identity and export extraction.")
    dll_proxy.add_argument("--copy-dir", required=True, help="Directory containing or receiving the explicit working copy.")
    dll_proxy.add_argument("--project-dir", default=None, help="Generated proxy project directory.")
    dll_proxy.add_argument("--architecture", choices=("x86", "x64", "arm64"), default=None)
    dll_proxy.add_argument("--proxy-name", default=None, help="Generated proxy DLL filename.")
    dll_proxy.set_defaults(func=dll_proxy_command)

    gui = subparsers.add_parser("gui", help="Run standalone GUI evidence transforms.")
    gui_commands = gui.add_subparsers(dest="gui_command", required=True)
    gui_project_world = gui_commands.add_parser(
        "project-world",
        help="Project explicit world coordinates into viewport evidence artifacts.",
    )
    gui_project_world.add_argument("--matrix", required=True, help="Inline JSON matrix or path to a JSON file.")
    gui_project_world.add_argument("--viewport", required=True, help="Inline JSON viewport or path to a JSON file.")
    gui_project_world.add_argument("--points", default=None, help="Inline JSON point list or path to a JSON file.")
    gui_project_world.add_argument("--aabbs", default=None, help="Inline JSON AABB list or path to a JSON file.")
    gui_project_world.add_argument("--out", required=True, help="Output root for gui/world_projection.json.")
    gui_project_world.add_argument("--matrix-layout", choices=("row-major", "column-major"), default="row-major")
    gui_project_world.add_argument("--clip-convention", choices=("d3d", "opengl"), default="d3d")
    gui_project_world.add_argument("--handedness", choices=("left-handed", "right-handed"), default="left-handed")
    gui_project_world.add_argument("--reversed-z", action="store_true")
    gui_project_world.add_argument("--matrix-source", default=None, help="Source label, inline JSON, or JSON file.")
    gui_project_world.add_argument("--coordinate-system", default=None, help="Coordinate-system label, inline JSON, or JSON file.")
    gui_project_world.add_argument("--metadata", default=None, help="Optional inline metadata JSON or JSON file.")
    gui_project_world.set_defaults(func=gui_world_projection_command)

    patch_binary = subparsers.add_parser("patch-binary", help="Validate/apply a patch plan or restore a patched binary to a new output file.")
    patch_commands = patch_binary.add_subparsers(dest="patch_command", required=True)
    apply_binary = patch_commands.add_parser("apply", help="Validate or apply an offline binary patch plan to a new output file.")
    apply_binary.add_argument("sample", help="Input binary/file; it is never modified in place.")
    apply_binary.add_argument("--plan", required=True, help="JSON patch plan containing guarded replace/AOB/append operations.")
    apply_binary.add_argument("--out", required=True, help="Output path; must differ from the input sample.")
    apply_binary.add_argument("--apply", action="store_true", help="Write the patched output; without this flag, run a full dry-run only.")
    apply_binary.add_argument("--artifact-dir", default=None, help="Directory for patch audit and rollback plan artifacts.")
    apply_binary.set_defaults(func=binary_patch_command)

    rollback_binary = patch_commands.add_parser("rollback", help="Dry-run or restore a patched binary to a separate output path.")
    rollback_binary.add_argument("patched", help="Patched binary/file; it is never modified in place.")
    rollback_binary.add_argument("--rollback", required=True, help="Rollback JSON manifest emitted by patch-binary --apply.")
    rollback_binary.add_argument("--out", required=True, help="Restored output path; must differ from the patched input.")
    rollback_binary.add_argument("--apply", action="store_true", help="Write the restored output; without this flag, run a full dry-run only.")
    rollback_binary.add_argument("--artifact-dir", default=None, help="Directory for rollback audit artifacts.")
    rollback_binary.set_defaults(func=binary_patch_rollback_command)

    validate_patch = subparsers.add_parser(
        "validate-patch-plan",
        help="Validate a patch plan without writing a patched binary; persist capability audit artifacts.",
    )
    validate_patch.add_argument("sample", help="Input binary/file used for target hash and pre-image validation.")
    validate_patch.add_argument("--plan", required=True, help="JSON patch plan to validate.")
    validate_patch.set_defaults(func=validate_patch_plan_command)

    evidence = subparsers.add_parser("evidence", help="Verify portable, hash-backed analysis evidence manifests.")
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_verify = evidence_commands.add_parser("verify", help="Verify hashes and relative paths recorded by an evidence manifest.")
    evidence_verify.add_argument("--manifest", required=True, help="Path to evidence-manifest.json.")
    evidence_verify.set_defaults(func=evidence_verify_command)

    environment_parser = subparsers.add_parser(
        "environment",
        help="Inspect optional adapter dependencies and run bounded readiness probes.",
    )
    environment_commands = environment_parser.add_subparsers(dest="environment_command", required=True)
    environment_validate = environment_commands.add_parser(
        "validate",
        help="Separate discovered dependencies from executed E2E readiness probes.",
    )
    environment_validate.add_argument(
        "--out",
        default=None,
        help="Optional JSON path or directory; directories receive environment-validation.json.",
    )
    environment_validate.add_argument("--json", action="store_true", help="Print the complete validation report.")
    environment_validate.add_argument(
        "--execute-probes",
        action="store_true",
        help="Execute bounded version/capability probes for discovered tools and bridges.",
    )
    environment_validate.add_argument("--timeout", type=float, default=5.0, help="Per-probe timeout in seconds.")
    environment_validate.add_argument(
        "--set",
        action="append",
        default=None,
        metavar="KEY=VALUE",
        help="Override a dependency path or configuration value. Repeatable.",
    )
    environment_validate.add_argument(
        "--require",
        action="append",
        default=None,
        metavar="WORKFLOW",
        help="Return exit code 4 unless the named workflow has an executed successful probe.",
    )
    environment_validate.add_argument(
        "--acceptance-workspace",
        default=None,
        help="Optional workspace whose hash-verified acceptance records are merged into the report.",
    )
    environment_validate.set_defaults(func=environment_validate_command)

    environment_accept = environment_commands.add_parser(
        "accept",
        help="List, execute, and verify registered P0-P4 acceptance fixtures.",
    )
    acceptance_commands = environment_accept.add_subparsers(dest="acceptance_command", required=True)
    acceptance_list = acceptance_commands.add_parser("list", help="List registered fixtures and retained records.")
    acceptance_list.add_argument("--workspace", required=True, help="Acceptance workspace root.")
    acceptance_list.set_defaults(func=environment_accept_list_command)

    acceptance_run = acceptance_commands.add_parser("run", help="Execute one registered fixture without a shell.")
    acceptance_run.add_argument("--fixture", required=True, help="Registered fixture identifier.")
    acceptance_run.add_argument("--workspace", required=True, help="Workspace that receives immutable run artifacts and records.")
    acceptance_run.add_argument("--execute", action="store_true", help="Required explicit confirmation that the registered fixture may run.")
    acceptance_run.add_argument("--timeout", type=float, default=300.0, help="Fixture timeout in seconds.")
    acceptance_run.add_argument(
        "--target-identity",
        default=None,
        help="Inline JSON object or JSON file identifying the controlled target.",
    )
    acceptance_run.set_defaults(func=environment_accept_run_command)

    acceptance_verify = acceptance_commands.add_parser("verify", help="Recompute all retained artifact hashes for a record.")
    acceptance_verify.add_argument("--record", required=True, help="Acceptance record JSON path.")
    acceptance_verify.set_defaults(func=environment_accept_verify_command)

    init_knowledge = subparsers.add_parser("init-knowledge", help="Create the local knowledge scaffold.")
    init_knowledge.add_argument("--workspace", default=None, help="Workspace root; defaults to current directory.")
    init_knowledge.add_argument("--root", dest="workspace", help=argparse.SUPPRESS)
    init_knowledge.set_defaults(func=init_knowledge_command)

    show_knowledge = subparsers.add_parser("show-knowledge", help="Print the knowledge manifest.")
    show_knowledge.add_argument("--workspace", default=None, help="Workspace root; defaults to current directory.")
    show_knowledge.add_argument("--init-if-missing", action="store_true", help="Create the manifest before showing it.")
    show_knowledge.set_defaults(func=show_knowledge_command)

    list_tools = subparsers.add_parser("list-tools", help="List built-in and future runtime tools.")
    list_tools.add_argument("--json", action="store_true", help="Emit JSON.")
    list_tools.set_defaults(func=list_tools_command)
    return parser


def _normalize_patch_binary_arguments(argv: Sequence[str] | None) -> list[str]:
    """Preserve legacy and flags-first ``patch-binary`` command spellings.

    ``patch-binary`` originally implied an apply-plan operation, so existing
    callers can omit the explicit ``apply`` subcommand.  Insert that command
    even when the old caller placed its options before the input path.  A
    flags-first rollback invocation is inferred from ``--rollback`` as well.
    """

    normalized = list(sys.argv[1:] if argv is None else argv)
    try:
        patch_index = normalized.index("patch-binary")
    except ValueError:
        return normalized
    next_index = patch_index + 1
    if next_index >= len(normalized):
        return normalized
    next_token = normalized[next_index]
    if next_token in {"apply", "rollback", "-h", "--help"}:
        return normalized

    # Keep the old implicit-apply behavior when options precede the input
    # sample.  ``--rollback`` is unambiguous and makes the equivalent
    # flags-first restore spelling work too.
    command = "rollback" if "--rollback" in normalized[next_index:] else "apply"
    normalized.insert(next_index, command)
    return normalized


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(_normalize_patch_binary_arguments(argv))
    if getattr(args, "install_guide", None):
        tool = args.install_guide.lower()
        if tool == "ghidra":
            if ghidra_install_guide is None:
                print("Ghidra install guide is unavailable because tools could not be imported.", file=sys.stderr)
                return 3
            print(ghidra_install_guide()["guide"])
        elif tool == "frida":
            if frida_install_guide is None:
                print("Frida install guide is unavailable because tools could not be imported.", file=sys.stderr)
                return 3
            print(frida_install_guide()["guide"])
        elif tool == "procmon":
            if procmon_install_guide is None:
                print("Procmon install guide is unavailable because tools could not be imported.", file=sys.stderr)
                return 3
            print(procmon_install_guide()["guide"])
        else:
            parser.error("--install-guide currently supports only: ghidra, frida, procmon")
        return 0
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return int(args.func(args))


def _append_observation(
    tool_results: list[dict[str, Any]],
    result_container: Any,
    session: Any,
    session_store: Any,
    tool_name: str,
    tool_args: Mapping[str, Any],
    tool_result: Any,
) -> dict[str, Any]:
    raw = _tool_result_dict(tool_result)
    status = _result_status(tool_result)
    observation = {
        "tool_name": tool_name,
        "tool_args": dict(tool_args),
        "result": raw,
        "error": _result_error(tool_result),
        "iteration": len(tool_results) + 1,
        "ok": status == "ok",
        "status": status,
    }
    tool_results.append(observation)
    if hasattr(result_container, "tool_results"):
        result_container.tool_results = tool_results
    if session_store is not None and hasattr(session_store, "record_tool_call"):
        output = raw if isinstance(raw, dict) else {"value": raw}
        session_store.record_tool_call(
            session,
            tool_name,
            status=status,
            input=dict(tool_args),
            output=output,
            error=observation["error"],
            message=tool_name,
        )
    elif session is not None and hasattr(session, "tool_calls"):
        session.tool_calls.append(dict(observation))
    return observation


def _run_memory_analysis(
    tool_executor: Any,
    tool_results: list[dict[str, Any]],
    result: Any,
    session: Any,
    session_store: Any,
    sample: Path,
    out_dir: Path,
    *,
    attach_pid: int | None,
    plan_path: str | None,
) -> list[str]:
    """Collect optional read-only memory evidence without interrupting analysis.

    A live snapshot is deliberately limited to an explicit PID attachment.  A
    plan may still drive offline diffs and address mappings when no live target
    is available.
    """

    artifacts: list[str] = []
    plan, plan_error, plan_dir = _load_memory_plan(plan_path)
    captured_snapshot: Any = None

    def record(tool_name: str, tool_args: Mapping[str, Any], tool_result: Any) -> None:
        _append_observation(tool_results, result, session, session_store, tool_name, tool_args, tool_result)
        artifacts.extend(_record_artifacts(session, session_store, tool_result))

    if plan_error:
        record(
            "memory_diff",
            {"memory_plan": plan_path},
            {"tool": "memory_diff", "status": "failed", "error": plan_error, "data": {}},
        )
        return artifacts

    if attach_pid is None:
        record(
            "memory_snapshot",
            {"attach_pid": None, "out_dir": str(out_dir)},
            {
                "tool": "memory_snapshot",
                "status": "unavailable",
                "error": "memory snapshots require an explicit --attach-pid",
                "data": {},
            },
        )
    else:
        capture_options = plan.get("capture") or plan.get("snapshot_options") or {}
        if not isinstance(capture_options, Mapping):
            capture_options = {}
        snapshot_args = {
            "path": attach_pid,
            "out_dir": str(out_dir),
            "module_filter": capture_options.get("module_filter"),
            "max_bytes": capture_options.get("max_bytes", 64 * 1024),
        }
        if "max_regions" in capture_options:
            snapshot_args["max_regions"] = capture_options.get("max_regions")
        snapshot_result = tool_executor.execute("memory_snapshot", **snapshot_args)
        captured_snapshot = _result_payload(snapshot_result) if _result_status(snapshot_result) == "ok" else None
        record(
            "memory_snapshot",
            {
                "attach_pid": attach_pid,
                "out_dir": str(out_dir),
                "module_filter": capture_options.get("module_filter"),
                "max_bytes": capture_options.get("max_bytes", 64 * 1024),
                "max_regions": capture_options.get("max_regions"),
            },
            snapshot_result,
        )

    diff_stages = _memory_plan_stages(plan, "diff", "memory_diff")
    for index, spec in enumerate(diff_stages):
        before = _memory_plan_source(spec.get("before", spec.get("before_snapshot")), captured_snapshot, plan_dir)
        after = _memory_plan_source(spec.get("after", spec.get("after_snapshot")), captured_snapshot, plan_dir)
        if before is None or after is None:
            record(
                "memory_diff",
                {"memory_plan": plan_path, "stage": index},
                {
                    "tool": "memory_diff",
                    "status": "failed",
                    "error": "memory diff plan entries require before and after snapshots",
                    "data": {},
                },
            )
            continue
        artifact_name = _memory_stage_artifact_name("memory_diff", index, len(diff_stages))
        diff_args = {"before": before, "after": after, "out_dir": str(out_dir)}
        if artifact_name is not None:
            diff_args["artifact_name"] = artifact_name
        diff_result = tool_executor.execute("memory_diff", **diff_args)
        record(
            "memory_diff",
            {"memory_plan": plan_path, "stage": index, "artifact_name": artifact_name},
            diff_result,
        )

    address_map_stages = _memory_plan_stages(plan, "address_map", "memory_address_map")
    for index, spec in enumerate(address_map_stages):
        snapshot = _memory_plan_source(
            spec.get("snapshot", spec.get("after", spec.get("after_snapshot", spec.get("before", spec.get("before_snapshot"))))),
            captured_snapshot,
            plan_dir,
        )
        addresses = spec.get("addresses")
        if snapshot is None or not isinstance(addresses, Sequence) or isinstance(addresses, (str, bytes, bytearray)):
            record(
                "memory_address_map",
                {"memory_plan": plan_path, "stage": index},
                {
                    "tool": "memory_address_map",
                    "status": "failed",
                    "error": "memory address-map plan entries require a snapshot and an addresses array",
                    "data": {},
                },
            )
            continue
        artifact_name = _memory_stage_artifact_name("memory_address_map", index, len(address_map_stages))
        map_args = {
            "path": str(spec.get("path") or sample),
            "snapshot": snapshot,
            "addresses": addresses,
            "out_dir": str(out_dir),
        }
        if artifact_name is not None:
            map_args["artifact_name"] = artifact_name
        map_result = tool_executor.execute("memory_address_map", **map_args)
        record(
            "memory_address_map",
            {
                "memory_plan": plan_path,
                "stage": index,
                "addresses": list(addresses),
                "artifact_name": artifact_name,
            },
            map_result,
        )

    return artifacts


def _load_memory_plan(plan_path: str | None) -> tuple[Mapping[str, Any], str | None, Path | None]:
    if not plan_path:
        return {}, None, None
    try:
        path = Path(plan_path).expanduser().resolve()
        # Accept the UTF-8 BOM emitted by Windows PowerShell's ``Set-Content``
        # as well as regular UTF-8 JSON produced by the CLI and editors.
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {}, f"invalid memory plan: {exc}", None
    if not isinstance(value, Mapping):
        return {}, "invalid memory plan: root must be a JSON object", None
    return value, None, path.parent


def _memory_plan_stages(plan: Mapping[str, Any], name: str, tool_name: str) -> list[Mapping[str, Any]]:
    value = plan.get(name, plan.get(tool_name, plan.get(f"{name}s")))
    if value is None:
        if name == "diff" and {"before", "after", "before_snapshot", "after_snapshot"}.intersection(plan):
            value = {
                "before": plan.get("before", plan.get("before_snapshot")),
                "after": plan.get("after", plan.get("after_snapshot")),
            }
        elif name == "address_map" and "addresses" in plan:
            value = {
                "snapshot": plan.get("snapshot", plan.get("after", plan.get("after_snapshot", plan.get("before", plan.get("before_snapshot"))))),
                "addresses": plan.get("addresses"),
                "path": plan.get("path"),
            }
        else:
            return []
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [item for item in value if isinstance(item, Mapping)]
    return [{}]


def _memory_stage_artifact_name(tool_name: str, index: int, stage_count: int) -> str | None:
    """Keep legacy names for single stages and disambiguate multi-stage plans."""

    if stage_count <= 1:
        return None
    return f"{tool_name}_stage_{index + 1}.json"


def _memory_plan_source(value: Any, captured_snapshot: Any, plan_dir: Path | None) -> Any:
    if isinstance(value, str):
        if value in {"current", "captured", "$snapshot"}:
            return captured_snapshot
        if plan_dir is not None:
            path = Path(value)
            return str(path if path.is_absolute() else (plan_dir / path).resolve())
    return value


def _register_reconstruction_runtime(session: Any, session_store: Any, reconstruct_result: Any) -> None:
    raw = _tool_result_dict(reconstruct_result)
    payload = raw.get("data") if isinstance(raw, Mapping) and "data" in raw else raw
    if not isinstance(payload, Mapping):
        return
    plan = payload.get("reconstruction_plan")
    if not isinstance(plan, Mapping):
        return
    project_dir = payload.get("project_dir")
    if session_store is not None and hasattr(session_store, "register_reconstruction_plan"):
        session_store.register_reconstruction_plan(
            session,
            plan,
            project_dir=project_dir,
            source_tool="reconstruct_project",
            metadata={
                "task_count": payload.get("task_count"),
                "next_task": payload.get("next_task"),
                "module_count": payload.get("module_count"),
            },
        )


def _gui_xaml_paths(resources: Mapping[str, Any] | None) -> list[str]:
    """Locate extracted XAML files deterministically without requiring a WPF runtime."""

    resources = resources or {}
    extracted_dir = resources.get("extracted_dir")
    root = Path(str(extracted_dir)) if extracted_dir else None
    candidates: list[Path] = []
    for value in resources.get("extracted_files") or []:
        if not isinstance(value, (str, Path)):
            continue
        candidate = Path(value)
        if not candidate.is_absolute() and root is not None:
            candidate = root / candidate
        if candidate.suffix.lower() == ".xaml" and candidate.is_file():
            candidates.append(candidate)
    if root is not None and root.is_dir():
        try:
            candidates.extend(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() == ".xaml")
        except OSError:
            pass
    seen: set[str] = set()
    paths: list[str] = []
    for candidate in sorted(candidates, key=lambda item: str(item).casefold()):
        key = str(candidate.resolve(strict=False)).casefold()
        if key not in seen:
            seen.add(key)
            paths.append(str(candidate))
    return paths


def _gui_decompiler_payload(tool_results: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Return the raw Ghidra payload so GUI event names can be linked to functions."""

    for trace in reversed(tool_results):
        if _trace_tool_name(trace) != "ghidra_decompile":
            continue
        payload = _trace_payload(trace)
        if isinstance(payload, Mapping):
            return dict(payload)
    return {}


def _load_gui_interaction_trace(path: str | Path | None) -> Any:
    """Load a user-supplied passive interaction trace without blocking analysis on bad input."""

    if not path:
        return None
    try:
        trace_path = Path(path)
        if trace_path.stat().st_size > _MAX_GUI_INTERACTION_TRACE_BYTES:
            return {
                "steps": [],
                "input_error": f"interaction trace exceeds {_MAX_GUI_INTERACTION_TRACE_BYTES} byte limit",
                "source_path": str(path),
            }
        payload = json.loads(trace_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {
            "steps": [],
            "input_error": f"{type(exc).__name__}: {exc}",
            "source_path": str(path),
        }
    if isinstance(payload, (list, Mapping)):
        return payload
    return {
        "steps": [],
        "input_error": "interaction trace JSON must be an object or array",
        "source_path": str(path),
    }


def _latest_tool_payload(tool_results: Sequence[Mapping[str, Any]], tool_name: str) -> Dict[str, Any]:
    for trace in reversed(tool_results):
        if _trace_tool_name(trace) != tool_name:
            continue
        payload = _trace_payload(trace)
        if isinstance(payload, Mapping):
            return dict(payload)
    return {}


def _behavior_dynamic_payload(tool_results: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Normalize trace observations into a compact behavior-graph dynamic input."""

    children = [
        _trace_payload(trace)
        for trace in tool_results
        if _trace_tool_name(trace) in {"frida_trace", "procmon_trace"} and isinstance(_trace_payload(trace), Mapping)
    ]
    if not children:
        return {}
    api_counts: Dict[str, int] = {}
    sample_events: list[Any] = []
    statuses: list[str] = []
    for payload in children:
        statuses.append(str(payload.get("status") or "ok").lower())
        for name, count in (payload.get("api_counts") or {}).items():
            api_counts[str(name)] = api_counts.get(str(name), 0) + _safe_int(count, default=0)
        sample_events.extend(list(payload.get("sample_events") or payload.get("events") or [])[:25])
    status = "failed" if "failed" in statuses else ("unavailable" if statuses and all(item == "unavailable" for item in statuses) else "ok")
    return {
        "status": status,
        "children": [dict(item) for item in children],
        "api_counts": api_counts,
        "sample_events": sample_events[:100],
        "event_count": sum(_safe_int(item.get("event_count"), default=0) for item in children),
    }


def _behavior_gui_analysis(tool_results: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    fingerprint = _latest_tool_payload(tool_results, "gui_fingerprint")
    evidence_graph = _latest_tool_payload(tool_results, "gui_evidence_graph")
    state_machine = _latest_tool_payload(tool_results, "gui_state_machine")
    strategy = _latest_tool_payload(tool_results, "gui_strategy_select")
    if not any((fingerprint, evidence_graph, state_machine, strategy)):
        return {}
    return {
        "status": "ok",
        "platform": fingerprint.get("platform"),
        "framework": fingerprint.get("framework"),
        "fingerprint": fingerprint,
        "evidence_graph": evidence_graph,
        "state_machine": state_machine,
        "strategy": strategy,
    }


def _run_behavior_graph(
    tool_executor: Any,
    tool_results: list[Any],
    result: Any,
    session: Any,
    session_store: Any,
    out_dir: Path,
) -> list[str]:
    """Generate one cross-domain graph for non-GUI or otherwise unhandled runs."""

    if any(_trace_tool_name(trace) == "gui_behavior_graph" for trace in tool_results):
        return []
    fingerprint = _latest_tool_payload(tool_results, "gui_fingerprint")
    resources = _latest_tool_payload(tool_results, "gui_resource_extract")
    decompiler = _gui_decompiler_payload(tool_results)
    dynamic_analysis = _behavior_dynamic_payload(tool_results)
    gui_analysis = _behavior_gui_analysis(tool_results)
    state_machine = gui_analysis.get("state_machine") if isinstance(gui_analysis.get("state_machine"), Mapping) else {}
    behavior_result = tool_executor.execute(
        "gui_behavior_graph",
        fingerprint=fingerprint,
        decompiler=decompiler,
        dynamic_analysis=dynamic_analysis,
        gui_analysis=gui_analysis,
        resources=resources,
        state_machine=state_machine,
        out_dir=str(out_dir),
    )
    _append_observation(
        tool_results,
        result,
        session,
        session_store,
        "gui_behavior_graph",
        {
            "fingerprint": fingerprint,
            "decompiler": decompiler,
            "dynamic_analysis": dynamic_analysis,
            "gui_analysis": gui_analysis,
            "resources": resources,
            "state_machine": state_machine,
            "out_dir": str(out_dir),
        },
        behavior_result,
    )
    return _record_artifacts(session, session_store, behavior_result)


def _run_engine_analysis(
    tool_executor: Any,
    tool_results: list[Any],
    result: Any,
    session: Any,
    session_store: Any,
    sample: Path,
    out_dir: Path,
) -> list[str]:
    engine_result = tool_executor.execute("engine_analyze", path=str(sample), out_dir=str(out_dir))
    _append_observation(
        tool_results,
        result,
        session,
        session_store,
        "engine_analyze",
        {"path": str(sample), "out_dir": str(out_dir)},
        engine_result,
    )
    return _record_artifacts(session, session_store, engine_result)


def _run_android_analysis(
    tool_executor: Any,
    tool_results: list[Any],
    result: Any,
    session: Any,
    session_store: Any,
    sample: Path,
    out_dir: Path,
) -> list[str]:
    android_result = tool_executor.execute("android_analyze", path=str(sample), out_dir=str(out_dir))
    _append_observation(
        tool_results,
        result,
        session,
        session_store,
        "android_analyze",
        {"path": str(sample), "out_dir": str(out_dir)},
        android_result,
    )
    return _record_artifacts(session, session_store, android_result)


def _run_ios_analysis(
    tool_executor: Any,
    tool_results: list[Any],
    result: Any,
    session: Any,
    session_store: Any,
    sample: Path,
    out_dir: Path,
) -> list[str]:
    ios_result = tool_executor.execute("ios_analyze", path=str(sample), out_dir=str(out_dir))
    _append_observation(
        tool_results,
        result,
        session,
        session_store,
        "ios_analyze",
        {"path": str(sample), "out_dir": str(out_dir)},
        ios_result,
    )
    return _record_artifacts(session, session_store, ios_result)


def _run_protocol_analysis(
    tool_executor: Any,
    tool_results: list[Any],
    result: Any,
    session: Any,
    session_store: Any,
    sample: Path,
    out_dir: Path,
) -> list[str]:
    protocol_result = tool_executor.execute(
        "protocol_analyze",
        path=str(sample),
        strings=_latest_tool_payload(tool_results, "strings_extract"),
        dynamic_analysis=_behavior_dynamic_payload(tool_results),
        behavior_graph=_latest_tool_payload(tool_results, "gui_behavior_graph"),
        semantic_ir=_latest_tool_payload(tool_results, "semantic_ir_build"),
        gui_analysis=_behavior_gui_analysis(tool_results),
        out_dir=str(out_dir),
    )
    _append_observation(
        tool_results,
        result,
        session,
        session_store,
        "protocol_analyze",
        {
            "path": str(sample),
            "out_dir": str(out_dir),
            "strings": "strings_extract",
            "dynamic_analysis": "derived",
            "behavior_graph": "gui_behavior_graph",
            "semantic_ir": "semantic_ir_build",
            "gui_analysis": "derived",
        },
        protocol_result,
    )
    return _record_artifacts(session, session_store, protocol_result)


def _run_semantic_ir(
    tool_executor: Any,
    tool_results: list[Any],
    result: Any,
    session: Any,
    session_store: Any,
    out_dir: Path,
) -> tuple[Any, list[str]]:
    """Build one deterministic IR from collected evidence without executing a sample."""

    behavior_graph = _latest_tool_payload(tool_results, "gui_behavior_graph")
    engine_analysis = _latest_tool_payload(tool_results, "engine_analyze")
    android_analysis = _latest_tool_payload(tool_results, "android_analyze")
    ios_analysis = _latest_tool_payload(tool_results, "ios_analyze")
    protocol_analysis = _latest_tool_payload(tool_results, "protocol_analyze")
    semantic_result = tool_executor.execute(
        "semantic_ir_build",
        behavior_graph=behavior_graph,
        decompiler=_gui_decompiler_payload(tool_results),
        dynamic_analysis=_behavior_dynamic_payload(tool_results),
        gui_analysis=_behavior_gui_analysis(tool_results),
        engine_analysis=engine_analysis,
        android_analysis=android_analysis,
        ios_analysis=ios_analysis,
        protocol_analysis=protocol_analysis,
        out_dir=str(out_dir),
    )
    _append_observation(
        tool_results,
        result,
        session,
        session_store,
        "semantic_ir_build",
        {
            "behavior_graph": behavior_graph,
            "decompiler": _gui_decompiler_payload(tool_results),
            "dynamic_analysis": _behavior_dynamic_payload(tool_results),
            "gui_analysis": _behavior_gui_analysis(tool_results),
            "engine_analysis": engine_analysis,
            "android_analysis": android_analysis,
            "ios_analysis": ios_analysis,
            "protocol_analysis": protocol_analysis,
            "out_dir": str(out_dir),
        },
        semantic_result,
    )
    return semantic_result, _record_artifacts(session, session_store, semantic_result)


def _run_gui_pipeline(
    tool_executor: Any,
    tool_results: list[Any],
    result: Any,
    session: Any,
    session_store: Any,
    sample: Path,
    out_dir: Path,
    args: argparse.Namespace,
    config: AnalyzerConfig,
) -> list[str]:
    artifacts: list[str] = []

    def execute_and_record(tool_name: str, input_payload: Mapping[str, Any], **kwargs: Any) -> tuple[Any, Any]:
        tool_result = tool_executor.execute(tool_name, **kwargs)
        _append_observation(tool_results, result, session, session_store, tool_name, dict(input_payload), tool_result)
        artifacts.extend(_record_artifacts(session, session_store, tool_result))
        return tool_result, _result_payload(tool_result)

    fingerprint_result, fingerprint = execute_and_record(
        "gui_fingerprint",
        {"path": str(sample), "out_dir": str(out_dir)},
        path=str(sample),
        out_dir=str(out_dir),
    )
    if _result_status(fingerprint_result) == "failed":
        return artifacts

    _, resources = execute_and_record(
        "gui_resource_extract",
        {"path": str(sample), "out_dir": str(out_dir)},
        path=str(sample),
        out_dir=str(out_dir),
    )

    xaml_evidence: Mapping[str, Any] = {}
    xaml_paths = _gui_xaml_paths(resources if isinstance(resources, Mapping) else {})
    detected_framework = str(fingerprint.get("framework") or "") if isinstance(fingerprint, Mapping) else ""
    if detected_framework == "wpf" or xaml_paths:
        _, xaml_payload = execute_and_record(
            "gui_xaml_extract",
            {"paths": xaml_paths, "out_dir": str(out_dir)},
            paths=xaml_paths,
            out_dir=str(out_dir),
        )
        xaml_evidence = xaml_payload if isinstance(xaml_payload, Mapping) else {}

    runtime_tree: Mapping[str, Any] = {}
    visual: Mapping[str, Any] = {}
    if args.gui_runtime:
        _, runtime_payload = execute_and_record(
            "gui_runtime_probe",
            {
                "path": str(sample),
                "out_dir": str(out_dir),
                "attach_pid": args.attach_pid,
                "adb_path": getattr(args, "adb_path", None),
                "android_serial": getattr(args, "android_serial", None),
            },
            path=str(sample),
            out_dir=str(out_dir),
            attach_pid=args.attach_pid,
            adb_path=getattr(args, "adb_path", None),
            android_serial=getattr(args, "android_serial", None),
        )
        runtime_tree = runtime_payload if isinstance(runtime_payload, Mapping) else {}
    if args.gui_visual:
        _, visual_payload = execute_and_record(
            "gui_visual_parse",
            {"screenshot_dir": args.gui_screenshot_dir, "out_dir": str(out_dir)},
            screenshot_dir=args.gui_screenshot_dir,
            out_dir=str(out_dir),
        )
        visual = visual_payload if isinstance(visual_payload, Mapping) else {}

    decompiler = _gui_decompiler_payload(tool_results)
    _, evidence_graph_payload = execute_and_record(
        "gui_evidence_graph",
        {
            "fingerprint": fingerprint,
            "resources": resources,
            "xaml_evidence": xaml_evidence,
            "runtime_tree": runtime_tree,
            "visual": visual,
            "decompiler": decompiler,
            "out_dir": str(out_dir),
        },
        fingerprint=fingerprint if isinstance(fingerprint, Mapping) else {},
        resources=resources if isinstance(resources, Mapping) else {},
        xaml_evidence=xaml_evidence,
        runtime_tree=runtime_tree,
        visual=visual,
        decompiler=decompiler,
        out_dir=str(out_dir),
    )
    evidence_graph = evidence_graph_payload if isinstance(evidence_graph_payload, Mapping) else {}

    interaction_trace = _load_gui_interaction_trace(getattr(args, "gui_interaction_trace", None))
    if interaction_trace is not None:
        if isinstance(interaction_trace, Mapping):
            trace_payload = dict(interaction_trace)
        elif isinstance(interaction_trace, list):
            trace_payload = {"steps": list(interaction_trace)}
        else:
            trace_payload = {"steps": [], "input_error": "unsupported interaction trace payload"}
        trace_payload.setdefault("status", "unavailable" if trace_payload.get("input_error") else "ok")
        trace_payload.setdefault("source_path", getattr(args, "gui_interaction_trace", None))
        _append_observation(
            tool_results,
            result,
            session,
            session_store,
            "gui_interaction_trace",
            {"path": getattr(args, "gui_interaction_trace", None)},
            trace_payload,
        )
    _, state_machine_payload = execute_and_record(
        "gui_state_machine",
        {
            "runtime_tree": runtime_tree,
            "visual": visual,
            "evidence_graph": evidence_graph,
            "interaction_trace": interaction_trace,
            "out_dir": str(out_dir),
        },
        runtime_tree=runtime_tree,
        visual=visual,
        evidence_graph=evidence_graph,
        interaction_trace=interaction_trace,
        out_dir=str(out_dir),
    )
    state_machine = state_machine_payload if isinstance(state_machine_payload, Mapping) else {}

    historical_strategy = _knowledge_gui_strategy_hint(
        config,
        str(fingerprint.get("framework") or "") if isinstance(fingerprint, Mapping) else None,
    )
    strategy_result, strategy = execute_and_record(
        "gui_strategy_select",
        {
            "fingerprint": fingerprint,
            "resources": resources,
            "runtime_tree": runtime_tree,
            "visual": visual,
            "evidence_graph": evidence_graph,
            "historical_strategy": historical_strategy,
            "target": args.gui_target,
            "out_dir": str(out_dir),
        },
        fingerprint=fingerprint if isinstance(fingerprint, Mapping) else {},
        resources=resources if isinstance(resources, Mapping) else {},
        runtime_tree=runtime_tree,
        visual=visual,
        evidence_graph=evidence_graph,
        historical_strategy=historical_strategy,
        target=args.gui_target,
        out_dir=str(out_dir),
    )
    if _result_status(strategy_result) == "failed":
        return artifacts

    gui_analysis = {
        "status": "ok",
        "platform": fingerprint.get("platform") if isinstance(fingerprint, Mapping) else None,
        "framework": fingerprint.get("framework") if isinstance(fingerprint, Mapping) else None,
        "confidence": fingerprint.get("confidence") if isinstance(fingerprint, Mapping) else None,
        "evidence": fingerprint.get("evidence") if isinstance(fingerprint, Mapping) else [],
        "fingerprint": fingerprint if isinstance(fingerprint, Mapping) else {},
        "resources": resources if isinstance(resources, Mapping) else {},
        "xaml_evidence": xaml_evidence,
        "evidence_graph": evidence_graph,
        "interaction_trace": interaction_trace if isinstance(interaction_trace, Mapping) else {"steps": interaction_trace or []},
        "state_machine": state_machine,
        "runtime_tree": runtime_tree,
        "visual": visual,
        "strategy": strategy if isinstance(strategy, Mapping) else {},
    }
    _, behavior_graph_payload = execute_and_record(
        "gui_behavior_graph",
        {
            "fingerprint": fingerprint,
            "decompiler": decompiler,
            "dynamic_analysis": _behavior_dynamic_payload(tool_results),
            "gui_analysis": gui_analysis,
            "resources": resources,
            "state_machine": state_machine,
            "out_dir": str(out_dir),
        },
        fingerprint=fingerprint if isinstance(fingerprint, Mapping) else {},
        decompiler=decompiler,
        dynamic_analysis=_behavior_dynamic_payload(tool_results),
        gui_analysis=gui_analysis,
        resources=resources if isinstance(resources, Mapping) else {},
        state_machine=state_machine,
        out_dir=str(out_dir),
    )
    if isinstance(behavior_graph_payload, Mapping):
        gui_analysis["behavior_graph"] = behavior_graph_payload
    if args.gui_visual or args.reconstruct_gui:
        execute_and_record(
            "gui_visual_regression",
            {"original_screenshot_dir": args.gui_screenshot_dir, "reconstructed_screenshot_dir": None, "out_dir": str(out_dir)},
            original_screenshot_dir=args.gui_screenshot_dir,
            reconstructed_screenshot_dir=None,
            out_dir=str(out_dir),
        )
    return artifacts


def _gui_reconstruction_analysis(tool_results: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Rebuild the GUI generator input after semantic IR evidence is available."""

    fingerprint = _latest_tool_payload(tool_results, "gui_fingerprint")
    strategy = _latest_tool_payload(tool_results, "gui_strategy_select")
    if not fingerprint and not strategy:
        return {}
    resources = _latest_tool_payload(tool_results, "gui_resource_extract")
    xaml_evidence = _latest_tool_payload(tool_results, "gui_xaml_extract")
    runtime_tree = _latest_tool_payload(tool_results, "gui_runtime_probe")
    visual = _latest_tool_payload(tool_results, "gui_visual_parse")
    evidence_graph = _latest_tool_payload(tool_results, "gui_evidence_graph")
    state_machine = _latest_tool_payload(tool_results, "gui_state_machine")
    interaction_trace = _latest_tool_payload(tool_results, "gui_interaction_trace")
    behavior_graph = _latest_tool_payload(tool_results, "gui_behavior_graph")
    return {
        "status": "ok",
        "platform": fingerprint.get("platform") if isinstance(fingerprint, Mapping) else None,
        "framework": fingerprint.get("framework") if isinstance(fingerprint, Mapping) else None,
        "confidence": fingerprint.get("confidence") if isinstance(fingerprint, Mapping) else None,
        "evidence": fingerprint.get("evidence") if isinstance(fingerprint, Mapping) else [],
        "fingerprint": fingerprint,
        "resources": resources,
        "xaml_evidence": xaml_evidence,
        "runtime_tree": runtime_tree,
        "visual": visual,
        "evidence_graph": evidence_graph,
        "interaction_trace": interaction_trace,
        "state_machine": state_machine,
        "strategy": strategy,
        "behavior_graph": behavior_graph,
    }


def _run_gui_reconstruction(
    tool_executor: Any,
    tool_results: list[Any],
    result: Any,
    session: Any,
    session_store: Any,
    sample: Path,
    out_dir: Path,
    semantic_ir: Mapping[str, Any],
) -> list[str]:
    """Generate and statically verify a GUI project using the completed IR."""

    strategy = _latest_tool_payload(tool_results, "gui_strategy_select")
    if strategy and str(strategy.get("status") or "ok").casefold() == "failed":
        return []
    gui_analysis = _gui_reconstruction_analysis(tool_results)
    if not gui_analysis:
        return []
    gui_analysis["semantic_ir"] = dict(semantic_ir)
    reconstruction_result = tool_executor.execute(
        "reconstruct_gui_project",
        path=str(sample),
        out_dir=str(out_dir),
        gui_analysis=gui_analysis,
        semantic_ir=semantic_ir,
    )
    _append_observation(
        tool_results,
        result,
        session,
        session_store,
        "reconstruct_gui_project",
        {
            "path": str(sample),
            "out_dir": str(out_dir),
            "gui_analysis": gui_analysis,
            "semantic_ir": dict(semantic_ir),
        },
        reconstruction_result,
    )
    artifacts = _record_artifacts(session, session_store, reconstruction_result)
    reconstruction_payload = _result_payload(reconstruction_result)
    project_dir = reconstruction_payload.get("project_dir") if isinstance(reconstruction_payload, Mapping) else None
    if not project_dir:
        return artifacts
    verification_result = tool_executor.execute(
        "reconstruction_verify",
        project_dir=str(project_dir),
        semantic_ir=semantic_ir,
    )
    _append_observation(
        tool_results,
        result,
        session,
        session_store,
        "reconstruction_verify",
        {"project_dir": str(project_dir), "semantic_ir": dict(semantic_ir), "reconstruction_kind": "gui"},
        verification_result,
    )
    artifacts.extend(_record_artifacts(session, session_store, verification_result))
    return artifacts


def _mark_flow_task(
    session: Any,
    session_store: Any,
    *,
    flow_name: str,
    task_name: str,
    status: str,
    result: Mapping[str, Any] | None = None,
    error: str | None = None,
    message: str = "",
) -> None:
    flow = _find_flow(session, flow_name)
    if flow is None:
        return
    task = _find_task(flow, task_name)
    if task is None:
        return
    task.set_status(status, result=dict(result or {}) or None, error=error)
    flow.refresh_status_from_tasks()
    if session is not None and hasattr(session, "refresh_status_from_flows"):
        session.refresh_status_from_flows()
    if session_store is not None and hasattr(session_store, "save"):
        session_store.save(session)
    if session_store is not None and hasattr(session_store, "record_event"):
        session_store.record_event(
            session,
            "flow_task_status_changed",
            message=message or "flow_task_status_changed",
            flow=flow.name,
            task=task.name,
            status=status,
            data={"result": dict(result or {}), "error": error},
        )


def _finalize_session_status(session: Any, session_store: Any, *, stopped_reason: str) -> None:
    if session is None:
        return
    if hasattr(session, "refresh_status_from_flows"):
        session.refresh_status_from_flows()
    current_status = getattr(getattr(session, "status", None), "value", getattr(session, "status", None))
    if stopped_reason == "repeated_tool":
        session.set_status("failed")
    elif stopped_reason == "barrier" and current_status in {None, "pending"}:
        session.set_status("running")
    elif stopped_reason in {"final_answer", "max_iterations"} and current_status == "pending":
        session.set_status("succeeded")
    if session_store is not None and hasattr(session_store, "save"):
        session_store.save(session)


def _find_flow(session: Any, flow_name: str) -> Any:
    for flow in getattr(session, "flows", []) or []:
        if getattr(flow, "name", None) == flow_name:
            return flow
    return None


def _find_task(flow: Any, task_name: str) -> Any:
    for task in getattr(flow, "tasks", []) or []:
        if getattr(task, "name", None) == task_name:
            return task
    return None


def _record_artifacts(session: Any, session_store: Any, tool_result: Any) -> list[str]:
    raw = _tool_result_dict(tool_result)
    payload = raw.get("data") if isinstance(raw, dict) and "data" in raw else raw
    collected: list[str] = []
    if not isinstance(payload, Mapping):
        return collected
    for item in payload.get("artifacts") or []:
        if not isinstance(item, Mapping) or not item.get("path"):
            continue
        path = str(item["path"])
        collected.append(path)
        if session_store is not None and hasattr(session_store, "record_artifact"):
            session_store.record_artifact(
                session,
                str(item.get("name") or Path(path).name),
                path=path,
                kind=str(item.get("kind") or "artifact"),
                data=dict(item),
            )
        elif session is not None and hasattr(session, "artifacts"):
            session.artifacts.append(dict(item))
    return collected


def _write_evidence_manifest(
    session: Any,
    session_store: Any,
    sample: Path,
    out_dir: Path,
    tool_results: Sequence[Mapping[str, Any]],
) -> Path | None:
    """Write a portable manifest for explicitly declared analysis artifacts.

    Reports and the manifest itself are intentionally excluded from the current
    manifest.  Including either would create a self-referential hash cycle;
    the manifest instead covers evidence emitted by analysis tools.
    """

    manifest_path = out_dir / "evidence-manifest.json"
    try:
        from .evidence import build_manifest, write_manifest
    except ImportError:
        from reverse_analyzer.evidence import build_manifest, write_manifest

    try:
        artifact_records = _manifest_artifact_records(session, tool_results)
        for name, kind in (("semantic_ir.json", "semantic-ir"), ("evidence_graph.json", "evidence-graph")):
            path = out_dir / name
            if path.is_file():
                artifact_records.append(
                    {
                        "name": name,
                        "path": str(path),
                        "kind": kind,
                        "tool": "platform_core_finalize",
                        "status": "ok",
                    }
                )
        manifest = build_manifest(
            out_dir,
            artifact_records,
            sample=sample,
            unavailable_stages=_manifest_unavailable_stages(tool_results),
        )
        manifest = write_manifest(manifest, manifest_path)
        summary = {
            "status": "ok",
            "manifest_path": manifest_path.name,
            "manifest_id": manifest.get("manifest_id"),
            "hash_algorithm": manifest.get("hash_algorithm", "sha256"),
            "covered_file_count": sum(1 for item in manifest.get("artifacts") or [] if isinstance(item, Mapping) and item.get("sha256")),
            "unavailable_stage_count": len(manifest.get("unavailable_stages") or []),
            "verification_command": "python -m reverse_analyzer evidence verify --manifest evidence-manifest.json",
        }
        _set_evidence_integrity(session, summary)
        artifact = {
            "name": manifest_path.name,
            "path": str(manifest_path),
            "kind": "evidence_manifest",
            "role": "integrity_manifest",
            "tool": "evidence_manifest",
            "status": "ok",
        }
        if session_store is not None and hasattr(session_store, "record_artifact"):
            session_store.record_artifact(
                session,
                manifest_path.name,
                path=manifest_path,
                kind="evidence_manifest",
                data=artifact,
            )
        elif session is not None and hasattr(session, "artifacts"):
            session.artifacts.append(artifact)
        return manifest_path
    except Exception as exc:  # noqa: BLE001 - evidence packaging must not discard an analysis report
        _set_evidence_integrity(
            session,
            {
                "status": "failed",
                "manifest_path": manifest_path.name,
                "covered_file_count": 0,
                "unavailable_stage_count": 0,
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
        print(f"evidence_manifest.failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None


def _set_evidence_integrity(session: Any, summary: Mapping[str, Any]) -> None:
    if session is None:
        return
    metadata = getattr(session, "metadata", None)
    if not isinstance(metadata, dict):
        metadata = dict(metadata) if isinstance(metadata, Mapping) else {}
        setattr(session, "metadata", metadata)
    metadata["evidence_integrity"] = dict(summary)


def _session_evidence_integrity(session: Any) -> dict[str, Any]:
    """Return the latest evidence-integrity summary stored on the session."""

    if session is None:
        return {}
    metadata = getattr(session, "metadata", None)
    if isinstance(metadata, Mapping):
        summary = metadata.get("evidence_integrity")
        if isinstance(summary, Mapping):
            return dict(summary)
    return {}


def _manifest_artifact_records(session: Any, tool_results: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Collect declared artifacts from session storage and trace payloads only."""

    records: list[dict[str, Any]] = []
    for item in getattr(session, "artifacts", []) or []:
        if not isinstance(item, Mapping):
            continue
        nested = item.get("data") if isinstance(item.get("data"), Mapping) else {}
        record = dict(nested)
        for key in ("name", "kind", "path", "flow", "task", "subtask"):
            if item.get(key) is not None and record.get(key) is None:
                record[key] = item.get(key)
        if _is_manifest_record(record):
            continue
        if record.get("path"):
            records.append(record)

    for trace_index, trace in enumerate(tool_results):
        tool_name = _trace_tool_name(trace)
        trace_status = _trace_status(trace)
        payload = _trace_payload(trace)
        if not isinstance(payload, Mapping):
            continue
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes, bytearray)):
            continue
        for artifact in artifacts:
            if not isinstance(artifact, Mapping) or not artifact.get("path"):
                continue
            record = dict(artifact)
            record.setdefault("tool", tool_name)
            record.setdefault("status", trace_status)
            record.setdefault("source_trace_index", trace_index)
            records.append(record)
    return records



def _is_manifest_record(record: Mapping[str, Any]) -> bool:
    """Evidence manifests are self-describing and must not cover themselves."""

    kind = str(record.get("kind") or "").lower()
    role = str(record.get("role") or "").lower()
    name = str(record.get("name") or Path(str(record.get("path") or "")).name).lower()
    return (
        kind == "evidence_manifest"
        or role == "integrity_manifest"
        or name == "evidence-manifest.json"
    )


def _manifest_unavailable_stages(tool_results: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    unavailable: list[dict[str, Any]] = []
    for trace_index, trace in enumerate(tool_results):
        status = _trace_status(trace).lower()
        if status not in {"unavailable", "skipped", "missing", "not_run", "not-run"}:
            continue
        payload = _trace_payload(trace)
        error = trace.get("error")
        if error is None and isinstance(payload, Mapping):
            error = payload.get("error") or payload.get("setup_hint")
        unavailable.append(
            {
                "tool": _trace_tool_name(trace) or "unknown",
                "status": status,
                "source_trace_index": trace_index,
                **({"reason": str(error)} if error else {}),
            }
        )
    return unavailable


def _build_reconstruction_analysis(tool_results: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    analysis: Dict[str, Any] = {"summary": {"source_tools": []}}
    summary = analysis["summary"]

    for trace in tool_results:
        tool_name = _trace_tool_name(trace)
        if tool_name:
            summary["source_tools"].append(tool_name)
        payload = _trace_payload(trace)
        if not isinstance(payload, Mapping):
            continue
        if tool_name == "pe_deep_scan":
            analysis.setdefault("imports", payload.get("imports") or [])
            summary["shell_score"] = payload.get("shell_score")
            summary["shell_verdict"] = payload.get("shell_verdict")
            summary["resource_types"] = (payload.get("resources") or {}).get("types") or []
        elif tool_name == "pe_header_scan" and not analysis.get("imports"):
            analysis["imports"] = payload.get("imports") or []
        elif tool_name == "ghidra_decompile":
            if payload.get("functions"):
                analysis["functions"] = payload.get("functions")
            if isinstance(payload.get("call_graph"), Mapping):
                analysis["call_graph"] = dict(payload.get("call_graph") or {})
            if payload.get("strings_xrefs"):
                analysis["strings_xrefs"] = list(payload.get("strings_xrefs") or [])
            if payload.get("imports_xrefs"):
                analysis["imports_xrefs"] = list(payload.get("imports_xrefs") or [])
            ghidra_summary = payload.get("summary")
            if isinstance(ghidra_summary, Mapping):
                summary["ghidra"] = dict(ghidra_summary)
                for source_key, target_key in (
                    ("program", "ghidra_program"),
                    ("language", "ghidra_language"),
                    ("compiler", "ghidra_compiler"),
                    ("image_base", "ghidra_image_base"),
                    ("string_count", "ghidra_string_count"),
                    ("import_count", "ghidra_import_count"),
                ):
                    if ghidra_summary.get(source_key) is not None:
                        summary[target_key] = ghidra_summary.get(source_key)
            summary["ghidra_function_count"] = payload.get("function_count")
            summary["ghidra_call_edge_count"] = len(((payload.get("call_graph") or {}).get("edges") or []))
            summary["ghidra_string_xref_count"] = len(payload.get("strings_xrefs") or [])
            summary["ghidra_import_xref_count"] = len(payload.get("imports_xrefs") or [])
        elif tool_name == "strings_extract":
            summary["string_count"] = payload.get("count")
        elif tool_name in {"yara_scan", "yara_scan_stub"}:
            summary["yara_match_count"] = payload.get("match_count")
            summary["yara_rules"] = [match.get("rule") for match in payload.get("matches") or [] if isinstance(match, Mapping)]
        elif tool_name in {"frida_trace", "procmon_trace"}:
            dynamic_items = _dynamic_evidence_from_payload(tool_name, payload)
            if dynamic_items:
                analysis.setdefault("dynamic_evidence", []).extend(dynamic_items)
            summary.setdefault("dynamic_backends", []).append(payload.get("backend") or tool_name.replace("_trace", ""))
            summary["dynamic_event_count"] = int(summary.get("dynamic_event_count") or 0) + int(payload.get("event_count") or 0)
        elif tool_name == "gui_behavior_graph":
            analysis["behavior_graph"] = dict(payload)
            graph_summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
            summary["behavior_graph_node_count"] = graph_summary.get("node_count", len(payload.get("nodes") or []))
            summary["behavior_graph_edge_count"] = graph_summary.get("edge_count", len(payload.get("edges") or []))
        elif tool_name == "semantic_ir_build":
            analysis["semantic_ir"] = dict(payload)
            semantic_summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
            semantic_entities = payload.get("entities") if isinstance(payload.get("entities"), list) else []
            semantic_relations = payload.get("relations") if isinstance(payload.get("relations"), list) else []
            semantic_capabilities = payload.get("capabilities") if isinstance(payload.get("capabilities"), list) else []
            summary["semantic_entity_count"] = semantic_summary.get("entity_count", len(semantic_entities))
            summary["semantic_relation_count"] = semantic_summary.get("relation_count", len(semantic_relations))
            summary["semantic_capability_count"] = semantic_summary.get("capability_count", len(semantic_capabilities))

    if "functions" not in analysis:
        analysis["functions"] = []
    if "imports" not in analysis:
        analysis["imports"] = []
    if "call_graph" not in analysis:
        analysis["call_graph"] = {"nodes": [], "edges": []}
    if "strings_xrefs" not in analysis:
        analysis["strings_xrefs"] = []
    if "imports_xrefs" not in analysis:
        analysis["imports_xrefs"] = []
    if "dynamic_evidence" not in analysis:
        analysis["dynamic_evidence"] = []
    if "behavior_graph" not in analysis:
        analysis["behavior_graph"] = {}
    return analysis


def _dynamic_evidence_from_payload(tool_name: str, payload: Mapping[str, Any]) -> list[Dict[str, Any]]:
    backend = str(payload.get("backend") or tool_name.replace("_trace", ""))
    evidence: list[Dict[str, Any]] = []

    api_counts = payload.get("api_counts")
    if isinstance(api_counts, Mapping):
        for name, count in api_counts.items():
            for module_name in _dynamic_modules_from_symbol(name):
                evidence.append(
                    {
                        "backend": backend,
                        "module": module_name,
                        "kind": "api",
                        "name": str(name),
                        "count": _safe_int(count, default=1),
                        "detail": f"{backend} observed API {name}",
                    }
                )

    operation_counts = payload.get("operation_counts")
    if isinstance(operation_counts, Mapping):
        for name, count in operation_counts.items():
            module_name = _dynamic_module_from_operation(name)
            if module_name:
                evidence.append(
                    {
                        "backend": backend,
                        "module": module_name,
                        "kind": "operation",
                        "name": str(name),
                        "count": _safe_int(count, default=1),
                        "detail": f"{backend} observed OS operation {name}",
                    }
                )

    category_counts = payload.get("category_counts")
    if isinstance(category_counts, Mapping):
        for name, count in category_counts.items():
            module_name = _dynamic_module_from_category(name)
            if module_name:
                evidence.append(
                    {
                        "backend": backend,
                        "module": module_name,
                        "kind": "category",
                        "name": str(name),
                        "count": _safe_int(count, default=1),
                        "detail": f"{backend} observed {name} behavior",
                    }
                )

    sample_events = payload.get("events") or payload.get("sample_events") or []
    if isinstance(sample_events, list):
        for event in sample_events[:25]:
            if not isinstance(event, Mapping):
                continue
            event_name = event.get("name") or event.get("operation")
            category = event.get("category")
            modules = _dynamic_modules_from_symbol(event_name) or []
            if not modules and category is not None:
                module_from_category = _dynamic_module_from_category(category)
                modules = [module_from_category] if module_from_category else []
            for module_name in modules:
                evidence.append(
                    {
                        "backend": backend,
                        "module": module_name,
                        "kind": "event",
                        "name": str(event_name or category or "event"),
                        "count": 1,
                        "detail": str(event.get("path") or event.get("result") or event.get("params") or "")[:200],
                    }
                )

    return _dedupe_dynamic_evidence(evidence)


def _dynamic_modules_from_symbol(value: Any) -> list[str]:
    lower = str(value or "").lower()
    modules: list[str] = []
    if any(token in lower for token in ("loadlibrary", "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress", "load image")):
        modules.append("loader")
    if any(token in lower for token in ("virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread", "ntcreatethread", "ntwritevirtualmemory", "createprocess", "winexec", "shellexecute", "process", "thread")):
        modules.append("process")
    if any(token in lower for token in ("winhttp", "internet", "urldownload", "connect", "send", "recv", "tcp", "udp", "getaddrinfo")):
        modules.append("network")
    if any(token in lower for token in ("crypt", "bcrypt", "md5", "sha", "aes", "rc4", "des", "tea", "xxtea")):
        modules.append("crypto")
    if any(token in lower for token in ("createfile", "readfile", "writefile", "reg", "file", "registry")) and "process" not in modules:
        modules.append("core")
    return list(dict.fromkeys(modules))


def _dynamic_module_from_operation(value: Any) -> Optional[str]:
    lower = str(value or "").lower()
    if lower.startswith("reg"):
        return "core"
    if lower.startswith(("createfile", "readfile", "writefile", "query", "set", "closefile")):
        return "core"
    if lower.startswith(("tcp", "udp")):
        return "network"
    if lower.startswith(("process", "thread")) or lower == "load image":
        return "process" if lower != "load image" else "loader"
    return None


def _dynamic_module_from_category(value: Any) -> Optional[str]:
    lower = str(value or "").lower()
    if lower in {"network"}:
        return "network"
    if lower in {"process", "exec", "memory", "anti_debug"}:
        return "process"
    if lower in {"loader"}:
        return "loader"
    if lower in {"file", "registry"}:
        return "core"
    return None


def _dedupe_dynamic_evidence(items: Sequence[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    merged: Dict[tuple[str, str, str, str], Dict[str, Any]] = {}
    for item in items:
        key = (
            str(item.get("backend") or ""),
            str(item.get("module") or ""),
            str(item.get("kind") or ""),
            str(item.get("name") or ""),
        )
        if key not in merged:
            merged[key] = dict(item)
            continue
        merged[key]["count"] = _safe_int(merged[key].get("count"), default=0) + _safe_int(item.get("count"), default=0)
        if not merged[key].get("detail") and item.get("detail"):
            merged[key]["detail"] = item.get("detail")
    return list(merged.values())


def _safe_int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, *, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _persist_knowledge(
    config: AnalyzerConfig,
    sample: Path,
    session: Any,
    out_dir: Path,
    report_data: Mapping[str, Any],
    tool_results: Sequence[Mapping[str, Any]],
) -> None:
    if KnowledgeBase is None:
        return
    try:
        knowledge = KnowledgeBase(config.knowledge_dir)
    except Exception as exc:
        _knowledge_base_warning("initialization", exc)
        return

    features = _knowledge_features(sample, report_data)
    observations = _knowledge_observations(tool_results, report_data)
    metadata = {
        "session_id": getattr(session, "session_id", None),
        "target": str(sample),
        "out_dir": str(out_dir),
        "status": (report_data.get("sample") or {}).get("status"),
    }
    evidence_integrity = _evidence_integrity_summary(report_data)
    if evidence_integrity.get("manifest_id"):
        metadata["manifest_id"] = evidence_integrity["manifest_id"]
    reverse_knowledge = _integrate_reverse_knowledge(
        knowledge,
        sample,
        session,
        features,
        report_data,
        evidence_integrity,
    )
    if isinstance(report_data, dict):
        report_data["knowledge_context"] = reverse_knowledge
    try:
        knowledge.upsert_sample(str(sample), features=features, metadata=metadata, observations=observations)
    except Exception as exc:
        _knowledge_base_warning("upsert_sample", exc)
        return

    try:
        dynamic_profile_records = _record_dynamic_profile_stats(knowledge, str(sample), report_data)
        recommended_dynamic_profile = knowledge.recommend_dynamic_profile() if hasattr(knowledge, "recommend_dynamic_profile") else {}
    except Exception as exc:
        _knowledge_base_warning("dynamic_profile_stats", exc)
        dynamic_profile_records = []
        recommended_dynamic_profile = {}

    try:
        gui_strategy_records = _record_gui_strategy_stats(knowledge, str(sample), report_data)
        gui_analysis = report_data.get("gui_analysis") if isinstance(report_data.get("gui_analysis"), Mapping) else {}
        recommended_gui_strategy = (
            knowledge.recommend_gui_strategy(framework=gui_analysis.get("framework"))
            if hasattr(knowledge, "recommend_gui_strategy")
            else {}
        )
    except Exception as exc:
        _knowledge_base_warning("gui_strategy_stats", exc)
        gui_strategy_records = []
        recommended_gui_strategy = {}

    try:
        patch_strategy_records = _record_patch_strategy_stats(knowledge, str(sample), report_data)
        patch_analysis = (
            report_data.get("patch_analysis")
            if isinstance(report_data.get("patch_analysis"), Mapping)
            else {}
        )
        patch_target_format = patch_analysis.get("target_format") or patch_analysis.get("format")
        recommended_patch_strategy = (
            knowledge.recommend_patch_strategy(target_format=patch_target_format)
            if hasattr(knowledge, "recommend_patch_strategy")
            else {}
        )
    except Exception as exc:
        _knowledge_base_warning("patch_strategy_stats", exc)
        patch_strategy_records = []
        recommended_patch_strategy = {}

    engine_strategy_records = _record_engine_strategy_stats(knowledge, str(sample), report_data)
    protocol_strategy_records = _record_protocol_strategy_stats(knowledge, str(sample), report_data)
    source_strategy_records = _record_source_strategy_stats(knowledge, str(sample), report_data)
    try:
        recommended_engine_strategy = knowledge.recommend_strategy("engine") if hasattr(knowledge, "recommend_strategy") else {}
        recommended_protocol_strategy = knowledge.recommend_strategy("protocol") if hasattr(knowledge, "recommend_strategy") else {}
        recommended_source_strategy = knowledge.recommend_strategy("source") if hasattr(knowledge, "recommend_strategy") else {}
    except Exception as exc:
        _knowledge_base_warning("generic_strategy_stats", exc)
        recommended_engine_strategy = {}
        recommended_protocol_strategy = {}
        recommended_source_strategy = {}

    try:
        knowledge.append_session_summary(
            {
                "session_id": getattr(session, "session_id", None),
                "target": str(sample),
                "status": metadata["status"],
                "out_dir": str(out_dir),
                "finding_count": len(report_data.get("findings") or []),
                "artifact_count": len(report_data.get("artifacts") or []),
                "dynamic_profile_records": dynamic_profile_records,
                "recommended_dynamic_profile": recommended_dynamic_profile,
                "gui_strategy_records": gui_strategy_records,
                "recommended_gui_strategy": recommended_gui_strategy,
                "patch_strategy_records": patch_strategy_records,
                "recommended_patch_strategy": recommended_patch_strategy,
                "engine_strategy_records": engine_strategy_records,
                "recommended_engine_strategy": recommended_engine_strategy,
                "protocol_strategy_records": protocol_strategy_records,
                "recommended_protocol_strategy": recommended_protocol_strategy,
                "source_strategy_records": source_strategy_records,
                "recommended_source_strategy": recommended_source_strategy,
                "behavior_graph": _behavior_graph_summary(report_data),
                "semantic_ir": _semantic_ir_summary(report_data),
                "reconstruction_verification": _reconstruction_verification_summary(report_data),
                "evidence_integrity": evidence_integrity,
                "platform_core": report_data.get("platform_core", {}),
                "knowledge_context": reverse_knowledge,
            }
        )
    except Exception as exc:
        _knowledge_base_warning("session_summary", exc)


def _knowledge_base_warning(stage: str, exc: Exception) -> None:
    """Keep optional knowledge persistence observable without failing analysis."""

    print(f"knowledge_base.{stage}_failed: {type(exc).__name__}: {exc}", file=sys.stderr)


def _integrate_reverse_knowledge(
    knowledge: Any,
    sample: Path,
    session: Any,
    features: Mapping[str, Any],
    report_data: Mapping[str, Any],
    evidence_integrity: Mapping[str, Any],
) -> Dict[str, Any]:
    """Recall prior reverse knowledge and persist a compact evidence-backed memory."""

    query = _reverse_knowledge_query(features)
    try:
        matches = knowledge.search_documents(query, limit=5) if query else []
    except Exception as exc:
        _knowledge_base_warning("reverse_knowledge_search", exc)
        matches = []

    recalled = [
        {
            "score": item.get("score"),
            "id": (item.get("document") or {}).get("id"),
            "type": (item.get("document") or {}).get("type"),
            "title": (item.get("document") or {}).get("title"),
            "scope": (item.get("document") or {}).get("scope"),
            "tags": (item.get("document") or {}).get("tags") or [],
        }
        for item in matches
        if isinstance(item, Mapping) and isinstance(item.get("document"), Mapping)
    ]
    result: Dict[str, Any] = {
        "status": "recalled" if recalled else "no_match",
        "query": query,
        "match_count": len(recalled),
        "matches": recalled,
        "stored_document_id": None,
    }

    document = _reverse_knowledge_document(sample, session, features, report_data, evidence_integrity)
    if document is None:
        result["storage_status"] = "skipped_no_verified_evidence"
        return result
    try:
        stored = knowledge.add_document(**document)
    except Exception as exc:
        _knowledge_base_warning("reverse_knowledge_store", exc)
        result["storage_status"] = "failed"
        return result
    result["storage_status"] = "stored"
    result["stored_document_id"] = stored.get("id")
    return result


def _reverse_knowledge_query(features: Mapping[str, Any]) -> str:
    terms: list[str] = []
    for namespace in ("sample", "pe", "yara", "dynamic", "semantic", "decompiler", "reconstruction"):
        values = features.get(namespace)
        if not isinstance(values, Mapping):
            continue
        for key, value in values.items():
            if value in (None, "", [], {}, False, 0):
                continue
            if isinstance(value, Mapping):
                terms.extend(str(item) for item in value.keys())
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                terms.extend(str(item) for item in value[:12])
            else:
                terms.extend((str(key), str(value)))
    return " ".join(dict.fromkeys(term.strip().lower() for term in terms if term.strip()))[:2000]


def _reverse_knowledge_document(
    sample: Path,
    session: Any,
    features: Mapping[str, Any],
    report_data: Mapping[str, Any],
    evidence_integrity: Mapping[str, Any],
) -> Optional[Dict[str, Any]]:
    evidence: Dict[str, Any] = {}
    for namespace in ("pe", "yara", "dynamic", "semantic", "decompiler", "reconstruction"):
        values = features.get(namespace)
        if not isinstance(values, Mapping):
            continue
        compact = {
            key: value
            for key, value in values.items()
            if value not in (None, "", [], {}, False, 0, "unknown", "unavailable")
        }
        if compact:
            evidence[namespace] = compact
    raw_findings = report_data.get("findings")
    findings_source = raw_findings if isinstance(raw_findings, Sequence) and not isinstance(raw_findings, (str, bytes, bytearray)) else []
    findings = [
        {
            "title": item.get("title") or item.get("name") or item.get("kind"),
            "severity": item.get("severity"),
        }
        for item in findings_source[:20]
        if isinstance(item, Mapping)
    ]
    if findings:
        evidence["findings"] = findings
    if not evidence:
        return None

    suffix = sample.suffix.lower().lstrip(".") or "binary"
    tags = {"reverse", suffix}
    for namespace in ("dynamic", "semantic", "reconstruction"):
        values = evidence.get(namespace)
        if not isinstance(values, Mapping):
            continue
        for key in ("backend", "hook_profile"):
            if values.get(key):
                tags.add(str(values[key]).lower())
        for key in ("capabilities", "prioritized_modules", "top_api_names"):
            for value in values.get(key) or []:
                tags.add(str(value).lower())
    payload = {
        "target_name": sample.name,
        "target_type": suffix,
        "evidence": evidence,
        "evidence_integrity": dict(evidence_integrity),
    }
    return {
        "content": json.dumps(payload, ensure_ascii=False, sort_keys=True),
        "document_type": "memory",
        "title": f"Reverse analysis: {sample.name}",
        "scope": f"reverse:{suffix}",
        "tags": sorted(tags),
        "metadata": {
            "session_id": getattr(session, "session_id", None),
            "target": str(sample),
            "manifest_id": evidence_integrity.get("manifest_id"),
            "evidence_backed": True,
        },
    }


def _evidence_integrity_summary(report_data: Mapping[str, Any]) -> dict[str, Any]:
    """Keep the session-history evidence reference compact and portable."""

    source = report_data.get("evidence_integrity")
    if not isinstance(source, Mapping):
        return {}
    return {
        key: source[key]
        for key in ("manifest_id", "manifest_path", "covered_file_count", "unavailable_stage_count", "status")
        if source.get(key) is not None
    }


def _record_dynamic_profile_stats(knowledge: Any, sample_id: str, report_data: Mapping[str, Any]) -> list[Dict[str, Any]]:
    dynamic = report_data.get("dynamic_analysis") or {}
    if not isinstance(dynamic, Mapping) or not hasattr(knowledge, "record_dynamic_profile_result"):
        return []
    children = dynamic.get("children") if isinstance(dynamic.get("children"), list) else [dynamic]
    records: list[Dict[str, Any]] = []
    for item in children:
        if not isinstance(item, Mapping):
            continue
        backend = str(item.get("backend") or "")
        profile = item.get("hook_profile")
        if backend not in {"frida", "all"} or not profile or profile == "custom":
            continue
        records.append(
            knowledge.record_dynamic_profile_result(
                str(profile),
                backend=backend,
                status=str(item.get("status") or "unknown"),
                event_count=_safe_int(item.get("event_count"), default=0),
                return_event_count=_safe_int(item.get("return_event_count"), default=0),
                planned_hook_count=_safe_int(item.get("planned_hook_count"), default=0),
                category_counts=item.get("category_counts") if isinstance(item.get("category_counts"), Mapping) else {},
                sample_id=sample_id,
            )
        )
    return records


def _record_gui_strategy_stats(knowledge: Any, sample_id: str, report_data: Mapping[str, Any]) -> list[Dict[str, Any]]:
    """Persist one GUI strategy outcome after a report has normalized all stages."""

    gui = report_data.get("gui_analysis") or {}
    if not isinstance(gui, Mapping) or not gui or not hasattr(knowledge, "record_gui_strategy_result"):
        return []
    strategy = gui.get("strategy") or {}
    if not isinstance(strategy, Mapping):
        return []
    strategy_name = strategy.get("name") or strategy.get("strategy")
    framework = gui.get("framework") or strategy.get("framework")
    if not strategy_name or not framework:
        return []
    regression = gui.get("regression") or {}
    regression = regression if isinstance(regression, Mapping) else {}
    return [
        knowledge.record_gui_strategy_result(
            str(framework),
            str(strategy_name),
            status=str(gui.get("status") or "unknown"),
            visual_similarity=_safe_float(regression.get("visual_similarity"), default=0.0),
            control_match_rate=_safe_float(regression.get("control_match_rate"), default=0.0),
            text_match_rate=_safe_float(regression.get("text_match_rate"), default=0.0),
            sample_id=sample_id,
        )
    ]


def _record_patch_strategy_stats(knowledge: Any, sample_id: str, report_data: Mapping[str, Any]) -> list[Dict[str, Any]]:
    """Persist a patch lifecycle outcome without treating unattempted stages as failures."""

    patch = report_data.get("patch_analysis")
    if not isinstance(patch, Mapping) or not hasattr(knowledge, "record_patch_strategy_result"):
        return []
    report_section = patch.get("report_section") if isinstance(patch.get("report_section"), Mapping) else {}
    source = {**report_section, **patch}
    action = str(source.get("action") or "").strip().lower()
    capability = str(source.get("capability") or "").strip().lower()

    strategy_value = source.get("strategy") or source.get("patch_strategy")
    if isinstance(strategy_value, Mapping):
        strategy_value = strategy_value.get("name") or strategy_value.get("key") or strategy_value.get("strategy")
    if not strategy_value:
        if capability != "patch_executor" and action not in {"plan", "validate", "apply", "rollback"}:
            return []
        strategy_value = "inline_patch"

    validation = source.get("validation") if isinstance(source.get("validation"), Mapping) else {}
    verification_status = source.get("verification_status")
    if verification_status is None and isinstance(validation.get("ok"), bool):
        verification_status = "ok" if validation["ok"] else "failed"
    if verification_status is None and isinstance(source.get("valid"), bool):
        verification_status = "ok" if source["valid"] else "failed"

    apply_status = source.get("apply_status")
    if apply_status is None and action == "apply":
        apply_status = source.get("status")

    rollback_status = source.get("rollback_status")
    rollback = source.get("rollback") if isinstance(source.get("rollback"), Mapping) else {}
    rollback_verification = (
        source.get("rollback_verification")
        if isinstance(source.get("rollback_verification"), Mapping)
        else {}
    )
    if rollback_status is None and isinstance(rollback.get("ok"), bool):
        rollback_status = "ok" if rollback["ok"] else "failed"
    if rollback_status is None and rollback_verification.get("status"):
        rollback_status = rollback_verification.get("status")
    if rollback_status is None and action == "rollback":
        rollback_status = source.get("status")

    risk_report = source.get("risk_report") if isinstance(source.get("risk_report"), Mapping) else {}
    risk_counts = source.get("risk_counts") if isinstance(source.get("risk_counts"), Mapping) else {}
    if not risk_counts and isinstance(risk_report.get("counts"), Mapping):
        risk_counts = risk_report["counts"]
    if not risk_counts and source.get("overall_risk"):
        risk_counts = {str(source["overall_risk"]): 1}

    after_snapshot = source.get("after_snapshot") if isinstance(source.get("after_snapshot"), Mapping) else {}
    operation_count = source.get("operation_count")
    if operation_count is None:
        operation_count = after_snapshot.get("operation_count")

    return [
        knowledge.record_patch_strategy_result(
            str(strategy_value),
            target_format=str(source.get("target_format") or source.get("format") or "pe"),
            status=str(source.get("status") or "unknown"),
            verification_status=str(verification_status) if verification_status is not None else None,
            apply_status=str(apply_status) if apply_status is not None else None,
            rollback_status=str(rollback_status) if rollback_status is not None else None,
            operation_count=_safe_int(operation_count, default=0),
            risk_counts=dict(risk_counts),
            sample_id=sample_id,
            backend=str(source.get("provider") or source.get("engine") or "") or None,
        )
    ]


def _record_engine_strategy_stats(knowledge: Any, sample_id: str, report_data: Mapping[str, Any]) -> list[Dict[str, Any]]:
    engine = report_data.get("engine_analysis")
    if not isinstance(engine, Mapping) or not hasattr(knowledge, "record_strategy_result"):
        return []
    strategy = engine.get("strategy") if isinstance(engine.get("strategy"), Mapping) else {}
    engine_name = str(engine.get("engine") or "unknown")
    strategy_name = str(strategy.get("name") or "static_engine_fingerprint")
    return [
        knowledge.record_strategy_result(
            "engine",
            f"{engine_name}:{strategy_name}",
            status=str(engine.get("status") or "unknown"),
            metrics={"confidence": _safe_float(engine.get("confidence"), default=0.0)},
            sample_id=sample_id,
        )
    ]


def _record_protocol_strategy_stats(knowledge: Any, sample_id: str, report_data: Mapping[str, Any]) -> list[Dict[str, Any]]:
    protocol = report_data.get("protocol_analysis")
    if not isinstance(protocol, Mapping) or not hasattr(knowledge, "record_strategy_result"):
        return []
    inference = protocol.get("inference") if isinstance(protocol.get("inference"), Mapping) else {}
    strategy = inference.get("strategy") if isinstance(inference.get("strategy"), Mapping) else {}
    key = str(strategy.get("key") or strategy.get("name") or "protocol:protocol_strings_dynamic_fusion")
    return [
        knowledge.record_strategy_result(
            "protocol",
            key,
            status=str(protocol.get("status") or "unknown"),
            metrics={
                "confidence": _safe_float(inference.get("confidence"), default=0.0),
                "flow_count": _safe_float((protocol.get("field_stats") or {}).get("protocol_count"), default=0.0),
            },
            sample_id=sample_id,
        )
    ]


def _record_source_strategy_stats(knowledge: Any, sample_id: str, report_data: Mapping[str, Any]) -> list[Dict[str, Any]]:
    source = report_data.get("source_reconstruction")
    if not isinstance(source, Mapping) or not hasattr(knowledge, "record_strategy_result"):
        return []
    strategy_name = str(source.get("strategy") or source.get("output_stack") or source.get("language") or "source_summary")
    return [
        knowledge.record_strategy_result(
            "source",
            f"source:{strategy_name}",
            status=str(source.get("status") or "unknown"),
            metrics={
                "source_file_count": _safe_float(source.get("source_file_count"), default=0.0),
                "function_count": _safe_float(source.get("function_count"), default=0.0),
                "verification_score": _safe_float(source.get("verification_score"), default=0.0),
            },
            sample_id=sample_id,
        )
    ]


def _behavior_graph_summary(report_data: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the compact behavior-graph metrics retained in session history."""

    behavior_graph = report_data.get("behavior_graph")
    if not isinstance(behavior_graph, Mapping) or not behavior_graph:
        return {}
    summary = behavior_graph.get("summary") if isinstance(behavior_graph.get("summary"), Mapping) else {}
    nodes = behavior_graph.get("nodes") if isinstance(behavior_graph.get("nodes"), list) else []
    edges = behavior_graph.get("edges") if isinstance(behavior_graph.get("edges"), list) else []
    return {
        "status": behavior_graph.get("status"),
        "node_count": _safe_int(summary.get("node_count"), default=len(nodes)),
        "edge_count": _safe_int(summary.get("edge_count"), default=len(edges)),
        "linked_handler_count": _safe_int(summary.get("linked_handler_count"), default=0),
        "dynamic_event_count": _safe_int(summary.get("dynamic_event_count"), default=0),
        "state_count": _safe_int(summary.get("state_count"), default=0),
        "transition_count": _safe_int(summary.get("transition_count"), default=0),
    }


def _semantic_ir_summary(report_data: Mapping[str, Any]) -> Dict[str, Any]:
    """Return compact semantic-IR metrics suitable for knowledge/session history."""

    semantic_ir = report_data.get("semantic_ir")
    if not isinstance(semantic_ir, Mapping) or not semantic_ir:
        return {}
    summary = semantic_ir.get("summary") if isinstance(semantic_ir.get("summary"), Mapping) else {}
    entities = semantic_ir.get("entities") if isinstance(semantic_ir.get("entities"), list) else []
    relations = semantic_ir.get("relations") if isinstance(semantic_ir.get("relations"), list) else []
    capabilities = semantic_ir.get("capabilities") if isinstance(semantic_ir.get("capabilities"), list) else []
    return {
        "status": semantic_ir.get("status"),
        "schema_version": semantic_ir.get("schema_version"),
        "entity_count": _safe_int(summary.get("entity_count"), default=len(entities)),
        "relation_count": _safe_int(summary.get("relation_count"), default=len(relations)),
        "capability_count": _safe_int(summary.get("capability_count"), default=len(capabilities)),
        "capabilities": [
            item.get("name") or item.get("category")
            for item in capabilities[:12]
            if isinstance(item, Mapping) and (item.get("name") or item.get("category"))
        ],
    }


def _reconstruction_verification_summary(report_data: Mapping[str, Any]) -> Dict[str, Any]:
    verification = report_data.get("reconstruction_verification")
    if not isinstance(verification, Mapping) or not verification:
        return {}
    coverage = verification.get("coverage") if isinstance(verification.get("coverage"), Mapping) else {}
    return {
        "status": verification.get("status"),
        "schema_version": verification.get("schema_version"),
        "score": verification.get("score"),
        "semantic_coverage": coverage.get("semantic_coverage"),
        "module_coverage": coverage.get("module_coverage"),
    }


def _knowledge_features(sample: Path, report_data: Mapping[str, Any]) -> Dict[str, Any]:
    pe = report_data.get("pe_analysis") or {}
    yara = report_data.get("yara") or {}
    dynamic = report_data.get("dynamic_analysis") or {}
    gui = report_data.get("gui_analysis") or {}
    decompiler = report_data.get("decompiler") or {}
    reconstruction = report_data.get("reconstruction") or {}
    gui = gui if isinstance(gui, Mapping) else {}
    gui_strategy = gui.get("strategy") if isinstance(gui.get("strategy"), Mapping) else {}
    gui_resources = gui.get("resources") if isinstance(gui.get("resources"), Mapping) else {}
    gui_runtime = gui.get("runtime_tree") if isinstance(gui.get("runtime_tree"), Mapping) else {}
    gui_visual = gui.get("visual") if isinstance(gui.get("visual"), Mapping) else {}
    gui_regression = gui.get("regression") if isinstance(gui.get("regression"), Mapping) else {}
    gui_xaml = gui.get("xaml_evidence") if isinstance(gui.get("xaml_evidence"), Mapping) else {}
    gui_evidence_graph = gui.get("evidence_graph") if isinstance(gui.get("evidence_graph"), Mapping) else {}
    gui_state_machine = gui.get("state_machine") if isinstance(gui.get("state_machine"), Mapping) else {}
    behavior_graph = report_data.get("behavior_graph") if isinstance(report_data.get("behavior_graph"), Mapping) else {}
    behavior_summary = behavior_graph.get("summary") if isinstance(behavior_graph.get("summary"), Mapping) else {}
    semantic_ir = report_data.get("semantic_ir") if isinstance(report_data.get("semantic_ir"), Mapping) else {}
    semantic_summary = semantic_ir.get("summary") if isinstance(semantic_ir.get("summary"), Mapping) else {}
    semantic_entities = semantic_ir.get("entities") if isinstance(semantic_ir.get("entities"), list) else []
    semantic_relations = semantic_ir.get("relations") if isinstance(semantic_ir.get("relations"), list) else []
    semantic_capabilities = semantic_ir.get("capabilities") if isinstance(semantic_ir.get("capabilities"), list) else []
    reconstruction_verification = (
        report_data.get("reconstruction_verification")
        if isinstance(report_data.get("reconstruction_verification"), Mapping)
        else {}
    )
    verification_coverage = (
        reconstruction_verification.get("coverage")
        if isinstance(reconstruction_verification.get("coverage"), Mapping)
        else {}
    )
    evidence_nodes = gui_evidence_graph.get("nodes") if isinstance(gui_evidence_graph.get("nodes"), list) else []
    evidence_edges = gui_evidence_graph.get("edges") if isinstance(gui_evidence_graph.get("edges"), list) else []
    event_handler_link_count = sum(
        len(node.get("handler_evidence") or [])
        for node in evidence_nodes
        if isinstance(node, Mapping)
    )
    return {
        "sample": {"suffix": sample.suffix or "", "size": sample.stat().st_size},
        "pe": {
            "shell_score": pe.get("shell_score"),
            "shell_verdict": pe.get("shell_verdict"),
            "import_dll_count": pe.get("import_dll_count"),
            "overlay_present": pe.get("overlay_present"),
            "section_anomaly_count": pe.get("section_anomaly_count"),
        },
        "yara": {
            "status": yara.get("status"),
            "match_count": yara.get("match_count"),
            "rules": [match.get("rule") for match in yara.get("matches") or [] if isinstance(match, Mapping)],
        },
        "dynamic": {
            "status": dynamic.get("status"),
            "backend": dynamic.get("backend"),
            "backends": dynamic.get("backends") or ([dynamic.get("backend")] if dynamic.get("backend") else []),
            "event_count": dynamic.get("event_count"),
            "return_event_count": dynamic.get("return_event_count"),
            "hook_profile": dynamic.get("hook_profile"),
            "planned_hook_count": dynamic.get("planned_hook_count"),
            "category_counts": dynamic.get("category_counts") or {},
            "top_api_names": list((dynamic.get("api_counts") or {}).keys())[:10],
            "top_operation_names": list((dynamic.get("operation_counts") or {}).keys())[:10],
            "top_paths": [
                item.get("path")
                for item in dynamic.get("top_paths") or []
                if isinstance(item, Mapping) and item.get("path")
            ][:10],
        },
        "gui": {
            "status": gui.get("status"),
            "platform": gui.get("platform"),
            "framework": gui.get("framework"),
            "confidence": gui.get("confidence"),
            "strategy": gui_strategy.get("name") or gui_strategy.get("strategy"),
            "output_stack": gui_strategy.get("output_stack"),
            "resource_counts": dict(gui_resources),
            "runtime_control_count": gui_runtime.get("control_count"),
            "visual_screenshot_count": gui_visual.get("screenshot_count"),
            "visual_similarity": gui_regression.get("visual_similarity"),
            "xaml_node_count": _safe_int(gui_xaml.get("node_count"), default=len(gui_xaml.get("nodes") or [])),
            "evidence_graph_node_count": len(evidence_nodes),
            "evidence_graph_edge_count": len(evidence_edges),
            "event_handler_link_count": event_handler_link_count,
            "state_count": _safe_int(gui_state_machine.get("summary", {}).get("state_count") if isinstance(gui_state_machine.get("summary"), Mapping) else None, default=len(gui_state_machine.get("states") or [])),
            "transition_count": _safe_int(gui_state_machine.get("summary", {}).get("transition_count") if isinstance(gui_state_machine.get("summary"), Mapping) else None, default=len(gui_state_machine.get("transitions") or [])),
            "action_count": _safe_int(gui_state_machine.get("summary", {}).get("action_count") if isinstance(gui_state_machine.get("summary"), Mapping) else None, default=len(gui_state_machine.get("actions") or [])),
        },
        "behavior": {
            "status": behavior_graph.get("status"),
            "node_count": _safe_int(behavior_summary.get("node_count"), default=len(behavior_graph.get("nodes") or [])),
            "edge_count": _safe_int(behavior_summary.get("edge_count"), default=len(behavior_graph.get("edges") or [])),
            "linked_handler_count": _safe_int(behavior_summary.get("linked_handler_count"), default=0),
            "dynamic_event_count": _safe_int(behavior_summary.get("dynamic_event_count"), default=0),
            "state_count": _safe_int(behavior_summary.get("state_count"), default=0),
            "transition_count": _safe_int(behavior_summary.get("transition_count"), default=0),
            "type_counts": behavior_summary.get("type_counts") or {},
        },
        "semantic": {
            "status": semantic_ir.get("status"),
            "schema_version": semantic_ir.get("schema_version"),
            "entity_count": _safe_int(semantic_summary.get("entity_count"), default=len(semantic_entities)),
            "relation_count": _safe_int(semantic_summary.get("relation_count"), default=len(semantic_relations)),
            "capability_count": _safe_int(semantic_summary.get("capability_count"), default=len(semantic_capabilities)),
            "capabilities": [
                item.get("name") or item.get("category")
                for item in semantic_capabilities[:12]
                if isinstance(item, Mapping) and (item.get("name") or item.get("category"))
            ],
        },
        "decompiler": {
            "status": decompiler.get("status"),
            "function_count": decompiler.get("function_count"),
        },
        "reconstruction": {
            "status": reconstruction.get("status"),
            "function_count": reconstruction.get("function_count"),
            "import_count": reconstruction.get("import_count"),
            "dynamic_evidence_count": _reconstruction_dynamic_evidence_count(reconstruction),
            "prioritized_modules": [
                item.get("module")
                for item in reconstruction.get("prioritized_modules") or []
                if isinstance(item, Mapping) and item.get("module")
            ],
            "verification_score": reconstruction_verification.get("score"),
            "semantic_coverage": verification_coverage.get("semantic_coverage"),
            "module_coverage": verification_coverage.get("module_coverage"),
        },
    }


def _knowledge_observations(tool_results: Sequence[Mapping[str, Any]], report_data: Mapping[str, Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for trace in tool_results:
        payload = _trace_payload(trace)
        tool_name = _trace_tool_name(trace)
        observations.append(
            {
                "kind": "tool",
                "tool": tool_name,
                "status": _trace_status(trace),
                "data": _tool_summary(payload),
            }
        )
        if tool_name in {"frida_trace", "procmon_trace"} and isinstance(payload, Mapping):
            observations.append(
                {
                    "kind": "dynamic_behavior",
                    "tool": tool_name,
                    "status": _trace_status(trace),
                    "data": _dynamic_observation_summary(payload),
                }
            )
    for item in report_data.get("findings") or []:
        if not isinstance(item, Mapping):
            continue
        observations.append(
            {
                "kind": "finding",
                "title": item.get("title"),
                "severity": item.get("severity"),
                "confidence": item.get("confidence"),
                "data": {"source": item.get("source"), "detail": item.get("detail")},
            }
        )
    dynamic = report_data.get("dynamic_analysis") or {}
    if isinstance(dynamic, Mapping) and dynamic:
        observations.append(
            {
                "kind": "dynamic_summary",
                "backend": dynamic.get("backend"),
                "status": dynamic.get("status"),
                "data": {
                    "event_count": dynamic.get("event_count"),
                    "category_counts": dynamic.get("category_counts") or {},
                    "api_counts": dict(list((dynamic.get("api_counts") or {}).items())[:10]),
                    "operation_counts": dict(list((dynamic.get("operation_counts") or {}).items())[:10]),
                    "top_paths": dynamic.get("top_paths") or [],
                },
            }
        )
    behavior_graph = report_data.get("behavior_graph") or {}
    if isinstance(behavior_graph, Mapping) and behavior_graph:
        behavior_summary = behavior_graph.get("summary") if isinstance(behavior_graph.get("summary"), Mapping) else {}
        observations.append(
            {
                "kind": "behavior_graph",
                "status": behavior_graph.get("status"),
                "data": {
                    "node_count": _safe_int(behavior_summary.get("node_count"), default=len(behavior_graph.get("nodes") or [])),
                    "edge_count": _safe_int(behavior_summary.get("edge_count"), default=len(behavior_graph.get("edges") or [])),
                    "linked_handler_count": _safe_int(behavior_summary.get("linked_handler_count"), default=0),
                    "dynamic_event_count": _safe_int(behavior_summary.get("dynamic_event_count"), default=0),
                    "state_count": _safe_int(behavior_summary.get("state_count"), default=0),
                    "transition_count": _safe_int(behavior_summary.get("transition_count"), default=0),
                },
            }
        )
    semantic_ir = report_data.get("semantic_ir") or {}
    if isinstance(semantic_ir, Mapping) and semantic_ir:
        observations.append(
            {
                "kind": "semantic_ir",
                "status": semantic_ir.get("status"),
                "data": _semantic_ir_summary(report_data),
            }
        )
    reconstruction_verification = report_data.get("reconstruction_verification") or {}
    if isinstance(reconstruction_verification, Mapping) and reconstruction_verification:
        observations.append(
            {
                "kind": "reconstruction_verification",
                "status": reconstruction_verification.get("status"),
                "data": _reconstruction_verification_summary(report_data),
            }
        )
    gui = report_data.get("gui_analysis") or {}
    if isinstance(gui, Mapping) and gui:
        strategy = gui.get("strategy") if isinstance(gui.get("strategy"), Mapping) else {}
        regression = gui.get("regression") if isinstance(gui.get("regression"), Mapping) else {}
        runtime_tree = gui.get("runtime_tree") if isinstance(gui.get("runtime_tree"), Mapping) else {}
        visual = gui.get("visual") if isinstance(gui.get("visual"), Mapping) else {}
        state_machine = gui.get("state_machine") if isinstance(gui.get("state_machine"), Mapping) else {}
        xaml_evidence = gui.get("xaml_evidence") if isinstance(gui.get("xaml_evidence"), Mapping) else {}
        evidence_graph = gui.get("evidence_graph") if isinstance(gui.get("evidence_graph"), Mapping) else {}
        evidence_nodes = evidence_graph.get("nodes") if isinstance(evidence_graph.get("nodes"), list) else []
        evidence_edges = evidence_graph.get("edges") if isinstance(evidence_graph.get("edges"), list) else []
        event_handler_link_count = sum(
            len(node.get("handler_evidence") or [])
            for node in evidence_nodes
            if isinstance(node, Mapping)
        )
        observations.append(
            {
                "kind": "gui_summary",
                "framework": gui.get("framework"),
                "status": gui.get("status"),
                "data": {
                    "platform": gui.get("platform"),
                    "confidence": gui.get("confidence"),
                    "strategy": strategy.get("name") or strategy.get("strategy"),
                    "output_stack": strategy.get("output_stack"),
                    "resources": gui.get("resources") or {},
                    "runtime_tree": {
                        "window_count": runtime_tree.get("window_count", 0),
                        "control_count": runtime_tree.get("control_count", 0),
                    },
                    "visual": {
                        "screenshot_count": visual.get("screenshot_count", 0),
                        "detected_widget_count": visual.get("detected_widget_count", 0),
                    },
                    "regression": {
                        "visual_similarity": regression.get("visual_similarity"),
                        "control_match_rate": regression.get("control_match_rate"),
                        "text_match_rate": regression.get("text_match_rate"),
                    },
                    "state_machine": {
                        "state_count": _safe_int(state_machine.get("summary", {}).get("state_count") if isinstance(state_machine.get("summary"), Mapping) else None, default=len(state_machine.get("states") or [])),
                        "transition_count": _safe_int(state_machine.get("summary", {}).get("transition_count") if isinstance(state_machine.get("summary"), Mapping) else None, default=len(state_machine.get("transitions") or [])),
                        "action_count": _safe_int(state_machine.get("summary", {}).get("action_count") if isinstance(state_machine.get("summary"), Mapping) else None, default=len(state_machine.get("actions") or [])),
                    },
                },
            }
        )
        if state_machine:
            state_summary = state_machine.get("summary") if isinstance(state_machine.get("summary"), Mapping) else {}
            observations.append(
                {
                    "kind": "gui_state_machine",
                    "framework": gui.get("framework"),
                    "status": state_machine.get("status") or gui.get("status"),
                    "data": {
                        "state_count": _safe_int(state_summary.get("state_count"), default=len(state_machine.get("states") or [])),
                        "transition_count": _safe_int(state_summary.get("transition_count"), default=len(state_machine.get("transitions") or [])),
                        "action_count": _safe_int(state_summary.get("action_count"), default=len(state_machine.get("actions") or [])),
                        "initial_state_id": state_summary.get("initial_state_id") or state_machine.get("initial_state"),
                    },
                }
            )
        if evidence_graph:
            observations.append(
                {
                    "kind": "gui_evidence_graph",
                    "framework": gui.get("framework"),
                    "status": evidence_graph.get("status") or gui.get("status"),
                    "data": {
                        "confidence": evidence_graph.get("confidence"),
                        "node_count": len(evidence_nodes),
                        "edge_count": len(evidence_edges),
                        "event_handler_link_count": event_handler_link_count,
                        "xaml_node_count": _safe_int(xaml_evidence.get("node_count"), default=len(xaml_evidence.get("nodes") or [])),
                        "source_summary": evidence_graph.get("source_summary") or {},
                    },
                }
            )
    return observations


def _dynamic_observation_summary(payload: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "backend": payload.get("backend"),
        "mode": payload.get("mode"),
        "hook_profile": payload.get("hook_profile"),
        "planned_hook_count": payload.get("planned_hook_count"),
        "event_count": payload.get("event_count"),
        "return_event_count": payload.get("return_event_count"),
        "category_counts": payload.get("category_counts") or {},
        "api_counts": dict(list((payload.get("api_counts") or {}).items())[:10]),
        "operation_counts": dict(list((payload.get("operation_counts") or {}).items())[:10]),
        "top_paths": payload.get("top_paths") or [],
        "artifacts": payload.get("artifacts") or [],
    }


def _reconstruction_dynamic_evidence_count(reconstruction: Mapping[str, Any]) -> int:
    value = reconstruction.get("dynamic_evidence_count")
    if value is not None:
        return _safe_int(value, default=0)
    for item in reconstruction.get("prioritized_modules") or []:
        if not isinstance(item, Mapping):
            continue
        dynamic_items = item.get("top_dynamic_evidence") or []
        if dynamic_items:
            return sum(len(module.get("top_dynamic_evidence") or []) for module in reconstruction.get("prioritized_modules") or [] if isinstance(module, Mapping))
    return 0


def _tool_summary(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {"value": payload}
    summary: Dict[str, Any] = {}
    for key in (
        "status",
        "match_count",
        "function_count",
        "score",
        "packed_likely",
        "shell_score",
        "shell_verdict",
        "project_dir",
        "platform",
        "framework",
        "strategy",
        "output_stack",
        "window_count",
        "control_count",
        "screenshot_count",
        "visual_similarity",
    ):
        if key in payload:
            summary[key] = payload.get(key)
    if not summary:
        summary["keys"] = sorted(payload.keys())[:10]
    return summary


def _trace_tool_name(trace: Mapping[str, Any]) -> str:
    return str(trace.get("tool_name") or trace.get("tool") or trace.get("name") or "")


def _trace_payload(trace: Mapping[str, Any]) -> Any:
    raw = trace.get("result") or trace.get("output")
    if hasattr(raw, "to_dict"):
        raw = raw.to_dict()
    if isinstance(raw, Mapping) and "data" in raw and ("status" in raw or "tool" in raw):
        return raw.get("data") or raw
    return raw


def _trace_status(trace: Mapping[str, Any]) -> str:
    if trace.get("status"):
        return str(trace["status"])
    raw = trace.get("result") or trace.get("output")
    if hasattr(raw, "to_dict"):
        raw = raw.to_dict()
    if isinstance(raw, Mapping) and raw.get("status"):
        return str(raw["status"])
    return "failed" if trace.get("error") else "ok"


def _tool_result_dict(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return value


def _result_payload(value: Any) -> Any:
    raw = _tool_result_dict(value)
    if isinstance(raw, Mapping) and "data" in raw:
        return raw.get("data") or raw
    return raw


_HARD_STAGE_STATUSES = frozenset({"failed", "error", "invalid", "cleanup_failed"})
_UNAVAILABLE_STAGE_STATUSES = frozenset(
    {"unavailable", "unsupported", "not_supported", "not_available"}
)


def _normalized_stage_status(value: Any) -> str:
    return str(value or "").strip().casefold().replace("-", "_")


def _result_status(value: Any) -> str:
    raw = _tool_result_dict(value)
    candidates: list[str] = []
    if hasattr(value, "status") and getattr(value, "status", None):
        candidates.append(str(getattr(value, "status")))
    if isinstance(raw, Mapping):
        if raw.get("status"):
            candidates.append(str(raw["status"]))
        nested = raw.get("data")
        if isinstance(nested, Mapping) and nested.get("status"):
            candidates.append(str(nested["status"]))
        wrapped = raw.get("result") or raw.get("output")
        if isinstance(wrapped, Mapping):
            if wrapped.get("status"):
                candidates.append(str(wrapped["status"]))
            wrapped_data = wrapped.get("data")
            if isinstance(wrapped_data, Mapping) and wrapped_data.get("status"):
                candidates.append(str(wrapped_data["status"]))

    normalized = [_normalized_stage_status(item) for item in candidates if str(item).strip()]
    for status in normalized:
        if status in _HARD_STAGE_STATUSES:
            return status
    if "partial" in normalized:
        return "partial"
    if any(status in _UNAVAILABLE_STAGE_STATUSES for status in normalized):
        return "unavailable"
    return normalized[0] if normalized else "ok"


def _aggregate_stage_outcome(
    tool_results: Sequence[Any],
    *,
    required_tools: Iterable[str],
    optional_tools: Iterable[str] = (),
    require_all: bool = False,
) -> dict[str, Any]:
    required = {str(item) for item in required_tools}
    optional = {str(item) for item in optional_tools}
    selected = required | optional
    stages: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, observation in enumerate(tool_results):
        if not isinstance(observation, Mapping):
            continue
        tool_name = _trace_tool_name(observation)
        if tool_name not in selected:
            continue
        seen.add(tool_name)
        raw_result = observation.get("result", observation.get("output", observation))
        status = _result_status(raw_result)
        normalized = _normalized_stage_status(status)
        is_required = tool_name in required
        hard_failure = normalized in _HARD_STAGE_STATUSES or (
            is_required and normalized in _UNAVAILABLE_STAGE_STATUSES
        )
        stages.append(
            {
                "name": tool_name,
                "index": index,
                "status": status,
                "required": is_required,
                "hard_failure": hard_failure,
            }
        )

    if require_all:
        for tool_name in sorted(required - seen):
            stages.append(
                {
                    "name": tool_name,
                    "index": None,
                    "status": "missing",
                    "required": True,
                    "hard_failure": True,
                }
            )

    failed_stages = [dict(item) for item in stages if item["hard_failure"]]
    partial_stages = [dict(item) for item in stages if item["status"] == "partial"]
    optional_unavailable = [
        dict(item)
        for item in stages
        if not item["required"] and _normalized_stage_status(item["status"]) in _UNAVAILABLE_STAGE_STATUSES
    ]
    if failed_stages:
        status = "failed"
    elif partial_stages:
        status = "partial"
    else:
        status = "succeeded"
    return {
        "status": status,
        "hard_failure": bool(failed_stages),
        "partial": bool(partial_stages),
        "stages": stages,
        "failed_stages": failed_stages,
        "partial_stages": partial_stages,
        "optional_unavailable_stages": optional_unavailable,
    }


def _stage_outcome_error(outcome: Mapping[str, Any]) -> str | None:
    failed = outcome.get("failed_stages")
    if not isinstance(failed, Sequence) or isinstance(failed, (str, bytes, bytearray)):
        return None
    summaries = [
        f"{item.get('name')}={item.get('status')}"
        for item in failed
        if isinstance(item, Mapping)
    ]
    return "required analysis stage failed: " + ", ".join(summaries) if summaries else None


def _result_error(value: Any) -> Any:
    if hasattr(value, "error"):
        return getattr(value, "error")
    if isinstance(value, Mapping):
        return value.get("error")
    return None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
