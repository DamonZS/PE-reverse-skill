"""Command-line entry points for the PentAGI migration scaffold."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

try:
    from .config import AnalyzerConfig, ensure_runtime_dirs, load_config, write_default_knowledge
    from .providers import RuleBasedProvider
    from .runtime import SessionStore, TraceLogger
    from .tools import ghidra_install_guide, register_builtin_tools
except ImportError:  # Allows direct script execution while package-level migration is incomplete.
    from config import AnalyzerConfig, ensure_runtime_dirs, load_config, write_default_knowledge
    RuleBasedProvider = None  # type: ignore[assignment]
    SessionStore = None  # type: ignore[assignment]
    TraceLogger = None  # type: ignore[assignment]
    register_builtin_tools = None  # type: ignore[assignment]
    ghidra_install_guide = None  # type: ignore[assignment]


_BUILTIN_TOOLS = [
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

    provider = RuleBasedProvider() if RuleBasedProvider is not None else None
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
    ghidra_artifacts: list[str] = []
    if args.decompile:
        ghidra_result = tool_executor.execute(
            "ghidra_decompile",
            path=str(sample),
            out_dir=str(out_dir),
            ghidra_home=args.ghidra_home,
            timeout=args.decompiler_timeout,
        )
        ghidra_observation = {
            "tool_name": "ghidra_decompile",
            "tool_args": {
                "path": str(sample),
                "out_dir": str(out_dir),
                "ghidra_home": args.ghidra_home,
                "timeout": args.decompiler_timeout,
            },
            "result": ghidra_result.to_dict() if hasattr(ghidra_result, "to_dict") else ghidra_result,
            "error": getattr(ghidra_result, "error", None),
            "iteration": len(tool_results) + 1,
            "ok": getattr(ghidra_result, "status", "ok") == "ok",
        }
        tool_results.append(ghidra_observation)
        if hasattr(result, "tool_results"):
            result.tool_results = tool_results
        ghidra_payload = ghidra_result.to_dict() if hasattr(ghidra_result, "to_dict") else ghidra_result
        if isinstance(ghidra_payload, dict):
            data = ghidra_payload.get("data") if "data" in ghidra_payload else ghidra_payload
            if isinstance(data, dict):
                for item in data.get("artifacts") or []:
                    if isinstance(item, dict) and item.get("path"):
                        session.artifacts.append(dict(item))
                        ghidra_artifacts.append(str(item["path"]))
        if getattr(ghidra_result, "status", "") == "unavailable":
            print("Ghidra Headless not configured. Run: python -m reverse_analyzer --install-guide ghidra", file=sys.stderr)
    if getattr(result, "stopped_reason", "") == "final_answer":
        session.set_status("succeeded")
    else:
        session.set_status("running")
    if session_store is not None:
        session_store.save(session)

    report_builder = _instantiate(loaded["ReportBuilder"], session, tool_results, {}, config=config, out_dir=out_dir)
    report_data = _call_first(report_builder, ("build", "render"))
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
                "artifacts": [str(report_json), str(report_md), *ghidra_artifacts],
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
        print(json.dumps(tools, indent=2))
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


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

