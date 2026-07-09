"""Command-line entry points for the PentAGI migration scaffold."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

try:
    from .config import AnalyzerConfig, ensure_runtime_dirs, load_config, write_default_knowledge
    from .knowledge import KnowledgeBase
    from .providers import RuleBasedProvider
    from .runtime import SessionStore, TraceLogger
    from .tools import ghidra_install_guide, register_builtin_tools
except ImportError:  # Allows direct script execution while package-level migration is incomplete.
    from config import AnalyzerConfig, ensure_runtime_dirs, load_config, write_default_knowledge

    KnowledgeBase = None  # type: ignore[assignment]
    RuleBasedProvider = None  # type: ignore[assignment]
    SessionStore = None  # type: ignore[assignment]
    TraceLogger = None  # type: ignore[assignment]
    ghidra_install_guide = None  # type: ignore[assignment]
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


def _new_session(sample: Path, out_dir: Path, max_iterations: int) -> Any:
    try:
        from .core.models import Flow, ReverseSession, Task
    except Exception as exc:
        raise RuntimeError(f"ReverseSession models are not importable: {exc}") from exc

    session = ReverseSession(
        target=str(sample),
        metadata={"out_dir": str(out_dir), "max_iterations": max_iterations, "migration": "pentagi"},
    )
    flow = Flow("binary-analysis", "PentAGI-style reverse-analysis flow")
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
        print("error: analysis runtime is incomplete; PentAGI orchestration modules are not ready.", file=sys.stderr)
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

    extra_artifacts: list[str] = []
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

    if args.reconstruct:
        analysis = _build_reconstruction_analysis(tool_results)
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

    if getattr(result, "stopped_reason", "") in {"final_answer", "max_iterations"}:
        session.set_status("succeeded")
    else:
        session.set_status("running")
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
    tools.append(ghidra_entry)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reverse_analyzer",
        description="PentAGI-style reverse analysis CLI scaffold.",
    )
    parser.add_argument("--install-guide", metavar="TOOL", help="Print setup instructions for an optional tool, e.g. ghidra.")
    subparsers = parser.add_subparsers(dest="command", required=False)

    analyze = subparsers.add_parser("analyze", help="Run an analysis session for a sample.")
    analyze.add_argument("sample", help="Path to the binary/sample to analyze.")
    analyze.add_argument("--out", required=True, help="Output directory for session artifacts and reports.")
    analyze.add_argument("--max-iterations", type=int, default=8, help="Maximum AgentLoop iterations.")
    analyze.add_argument("--decompile", action="store_true", help="Run Ghidra Headless decompilation when configured.")
    analyze.add_argument("--ghidra-home", default=None, help="Path to Ghidra root directory; overrides GHIDRA_HOME.")
    analyze.add_argument("--decompiler-timeout", type=int, default=900, help="Ghidra Headless timeout in seconds.")
    analyze.add_argument("--yara-rules", default=None, help="Optional YARA rule file or directory; defaults to rules/yara.")
    analyze.add_argument("--reconstruct", action="store_true", help="Generate a compilable reconstruction stub project in the output directory.")
    analyze.set_defaults(func=analyze_command)

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
        if args.install_guide.lower() != "ghidra":
            parser.error("--install-guide currently supports only: ghidra")
        if ghidra_install_guide is None:
            print("Ghidra install guide is unavailable because tools could not be imported.", file=sys.stderr)
            return 3
        print(ghidra_install_guide()["guide"])
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
            summary["ghidra_function_count"] = payload.get("function_count")
        elif tool_name == "strings_extract":
            summary["string_count"] = payload.get("count")
        elif tool_name in {"yara_scan", "yara_scan_stub"}:
            summary["yara_match_count"] = payload.get("match_count")
            summary["yara_rules"] = [match.get("rule") for match in payload.get("matches") or [] if isinstance(match, Mapping)]

    if "functions" not in analysis:
        analysis["functions"] = []
    if "imports" not in analysis:
        analysis["imports"] = []
    return analysis


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
    except Exception:
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
        knowledge.append_session_summary(
            {
                "session_id": getattr(session, "session_id", None),
                "target": str(sample),
                "status": metadata["status"],
                "out_dir": str(out_dir),
                "finding_count": len(report_data.get("findings") or []),
                "artifact_count": len(report_data.get("artifacts") or []),
            }
        )
    except Exception:
        return


def _knowledge_features(sample: Path, report_data: Mapping[str, Any]) -> Dict[str, Any]:
    pe = report_data.get("pe_analysis") or {}
    yara = report_data.get("yara") or {}
    decompiler = report_data.get("decompiler") or {}
    reconstruction = report_data.get("reconstruction") or {}
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
        "decompiler": {
            "status": decompiler.get("status"),
            "function_count": decompiler.get("function_count"),
        },
        "reconstruction": {
            "status": reconstruction.get("status"),
            "function_count": reconstruction.get("function_count"),
            "import_count": reconstruction.get("import_count"),
        },
    }


def _knowledge_observations(tool_results: Sequence[Mapping[str, Any]], report_data: Mapping[str, Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for trace in tool_results:
        payload = _trace_payload(trace)
        observations.append(
            {
                "kind": "tool",
                "tool": _trace_tool_name(trace),
                "status": _trace_status(trace),
                "data": _tool_summary(payload),
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
    return observations


def _tool_summary(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {"value": payload}
    summary: Dict[str, Any] = {}
    for key in ("status", "match_count", "function_count", "score", "packed_likely", "shell_score", "shell_verdict", "project_dir"):
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
