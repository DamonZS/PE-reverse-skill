"""Command-line entry points for the PE migration scaffold."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

try:
    from .config import AnalyzerConfig, ensure_runtime_dirs, load_config, write_default_knowledge
    from .dashboard import build_dashboard, serve_dashboard
    from .knowledge import KnowledgeBase
    from .providers import RuleBasedProvider
    from .runtime import ExperimentStore, SessionStore, TraceLogger
    from .tools import frida_install_guide, ghidra_install_guide, procmon_install_guide, register_builtin_tools
except ImportError:  # Allows direct script execution while package-level migration is incomplete.
    from config import AnalyzerConfig, ensure_runtime_dirs, load_config, write_default_knowledge

    KnowledgeBase = None  # type: ignore[assignment]
    RuleBasedProvider = None  # type: ignore[assignment]
    ExperimentStore = None  # type: ignore[assignment]
    SessionStore = None  # type: ignore[assignment]
    TraceLogger = None  # type: ignore[assignment]
    build_dashboard = None  # type: ignore[assignment]
    serve_dashboard = None  # type: ignore[assignment]
    frida_install_guide = None  # type: ignore[assignment]
    ghidra_install_guide = None  # type: ignore[assignment]
    procmon_install_guide = None  # type: ignore[assignment]
    register_builtin_tools = None  # type: ignore[assignment]


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
        "name": "procmon_trace",
        "status": "optional-dependency",
        "description": "Dynamic OS behavior capture with Microsoft Sysinternals Procmon PML/CSV artifacts.",
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


def binary_patch_command(args: argparse.Namespace) -> int:
    """Apply a guarded offline patch plan to a copied output binary."""

    try:
        from .tools import binary_patch_apply_plan
    except ImportError:
        from reverse_analyzer.tools import binary_patch_apply_plan

    result = binary_patch_apply_plan(
        args.sample,
        plan=args.plan,
        out_path=args.out,
        apply=bool(args.apply),
        artifact_dir=args.artifact_dir,
    )
    payload = result.to_dict() if hasattr(result, "to_dict") else result
    _print_json_payload(payload if isinstance(payload, Mapping) else {"status": "failed", "error": str(payload)})
    return 0 if getattr(result, "status", "failed") in {"ok", "planned"} else 2


_KNOWN_DYNAMIC_PROFILES = {"quick", "behavior", "unpacking", "network", "persistence"}
_MAX_GUI_INTERACTION_TRACE_BYTES = 1024 * 1024


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

    if session_store is not None:
        session_store.save(session)

    report_builder = _instantiate(loaded["ReportBuilder"], session, tool_results, {}, config=config, out_dir=out_dir)
    report_data = _call_first(report_builder, ("build", "render"))
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
                "result": result.to_dict() if hasattr(result, "to_dict") else result,
                "artifacts": [str(report_json), str(report_md), *extra_artifacts],
            },
            default=str,
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


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
    return {key: value for key, value in options.items() if value is not None and value is not False}


def _print_json_payload(payload: Mapping[str, Any]) -> None:
    print(json.dumps(dict(payload), ensure_ascii=False, indent=2, default=str))


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


def _add_experiment_analysis_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dynamic", action="store_true", help="Include optional dynamic tracing in the planned analysis command.")
    parser.add_argument("--dynamic-backend", choices=("frida", "procmon", "all"), default="frida")
    parser.add_argument("--dynamic-profile", choices=("auto", "behavior", "quick", "unpacking", "network", "persistence"), default="auto")
    parser.add_argument("--dynamic-duration", type=float, default=10.0)
    parser.add_argument("--gui", action="store_true", help="Include GUI fingerprinting and strategy selection.")
    parser.add_argument("--gui-runtime", action="store_true", help="Include optional runtime UI probing.")
    parser.add_argument("--gui-visual", action="store_true", help="Include GUI visual parsing.")
    parser.add_argument("--reconstruct", action="store_true", help="Include native reconstruction output.")
    parser.add_argument("--reconstruct-gui", action="store_true", help="Include GUI reconstruction output.")
    parser.add_argument("--gui-target", default="auto")
    parser.add_argument("--gui-interaction-trace", default=None)


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
    analyze.add_argument("--dynamic-hook-file", default=None, help="JSON hook plan for Frida; defaults to the built-in Windows reverse-analysis hooks.")
    analyze.add_argument("--procmon-path", default=None, help="Path to Procmon64.exe/Procmon.exe for --dynamic-backend procmon/all.")
    analyze.add_argument("--decompile", action="store_true", help="Run Ghidra Headless decompilation when configured.")
    analyze.add_argument("--ghidra-home", default=None, help="Path to Ghidra root directory; overrides GHIDRA_HOME.")
    analyze.add_argument("--decompiler-timeout", type=int, default=900, help="Ghidra Headless timeout in seconds.")
    analyze.add_argument("--yara-rules", default=None, help="Optional YARA rule file or directory; defaults to rules/yara.")
    analyze.add_argument("--reconstruct", action="store_true", help="Generate a compilable reconstruction stub project in the output directory.")
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

    patch_binary = subparsers.add_parser("patch-binary", help="Validate or apply an offline binary patch plan to a new output file.")
    patch_binary.add_argument("sample", help="Input binary/file; it is never modified in place.")
    patch_binary.add_argument("--plan", required=True, help="JSON patch plan containing guarded replace/AOB/append/insert operations.")
    patch_binary.add_argument("--out", required=True, help="Output path; must differ from the input sample.")
    patch_binary.add_argument("--apply", action="store_true", help="Write the patched output; without this flag, run a full dry-run only.")
    patch_binary.add_argument("--artifact-dir", default=None, help="Directory for patch audit and rollback plan artifacts.")
    patch_binary.set_defaults(func=binary_patch_command)

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


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
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
    semantic_result = tool_executor.execute(
        "semantic_ir_build",
        behavior_graph=behavior_graph,
        decompiler=_gui_decompiler_payload(tool_results),
        dynamic_analysis=_behavior_dynamic_payload(tool_results),
        gui_analysis=_behavior_gui_analysis(tool_results),
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
                "behavior_graph": _behavior_graph_summary(report_data),
                "semantic_ir": _semantic_ir_summary(report_data),
                "reconstruction_verification": _reconstruction_verification_summary(report_data),
            }
        )
    except Exception as exc:
        _knowledge_base_warning("session_summary", exc)


def _knowledge_base_warning(stage: str, exc: Exception) -> None:
    """Keep optional knowledge persistence observable without failing analysis."""

    print(f"knowledge_base.{stage}_failed: {type(exc).__name__}: {exc}", file=sys.stderr)


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


def _result_status(value: Any) -> str:
    if hasattr(value, "status"):
        return str(getattr(value, "status") or "ok").lower()
    if isinstance(value, Mapping):
        if value.get("status"):
            return str(value.get("status")).lower()
        nested = value.get("data")
        if isinstance(nested, Mapping) and nested.get("status"):
            return str(nested.get("status")).lower()
    return "ok"


def _result_error(value: Any) -> Any:
    if hasattr(value, "error"):
        return getattr(value, "error")
    if isinstance(value, Mapping):
        return value.get("error")
    return None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
