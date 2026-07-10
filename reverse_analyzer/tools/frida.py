"""Optional Frida-based dynamic tracing backend."""

from __future__ import annotations

import importlib
import json
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .executor import ToolResult


FRIDA_DOCS_URL = "https://frida.re/docs/installation/"
DEFAULT_DURATION = 10.0

FRIDA_HOOK_PROFILES: Dict[str, Dict[str, Any]] = {
    "behavior": {"description": "Broad behavior tracing across loader, memory, process, file, registry, and network APIs."},
    "quick": {
        "description": "Small high-signal hook set for low-overhead smoke runs.",
        "names": {
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc", "VirtualProtect",
            "CreateProcessA", "CreateProcessW", "WinHttpSendRequest", "connect", "send", "CreateFileW",
        },
    },
    "unpacking": {
        "description": "Loader, memory, anti-debug, and injection hooks for unpacking and runtime API resolution.",
        "categories": {"loader", "memory", "process", "anti_debug"},
    },
    "network": {
        "description": "Network and dynamic resolver hooks for protocol/API reconstruction.",
        "categories": {"loader", "network"},
    },
    "persistence": {
        "description": "File, registry, process, and loader hooks for installation/persistence behavior.",
        "categories": {"loader", "file", "registry", "process"},
    },
}
DEFAULT_HOOKS: tuple[Dict[str, Any], ...] = ({'module': 'kernel32.dll',
  'name': 'LoadLibraryA',
  'category': 'loader',
  'args': [{'index': 0, 'name': 'library', 'type': 'ansi'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'LoadLibraryW',
  'category': 'loader',
  'args': [{'index': 0, 'name': 'library', 'type': 'wide'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'GetProcAddress',
  'category': 'loader',
  'args': [{'index': 0, 'name': 'module_handle', 'type': 'pointer'},
           {'index': 1, 'name': 'symbol', 'type': 'ansi_or_ordinal'}],
  'capture_return': True},
 {'module': 'kernel32.dll', 'name': 'IsDebuggerPresent', 'category': 'anti_debug', 'args': [], 'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'CheckRemoteDebuggerPresent',
  'category': 'anti_debug',
  'args': [{'index': 0, 'name': 'process', 'type': 'pointer'},
           {'index': 1, 'name': 'is_debugger_present_ptr', 'type': 'pointer'}],
  'capture_return': True},
 {'module': 'ntdll.dll',
  'name': 'NtQueryInformationProcess',
  'category': 'anti_debug',
  'args': [{'index': 0, 'name': 'process', 'type': 'pointer'},
           {'index': 1, 'name': 'process_information_class', 'type': 'u32'},
           {'index': 2, 'name': 'process_information', 'type': 'pointer'},
           {'index': 3, 'name': 'process_information_length', 'type': 'u32'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'VirtualAlloc',
  'category': 'memory',
  'args': [{'index': 0, 'name': 'address', 'type': 'pointer'},
           {'index': 1, 'name': 'size', 'type': 'u64'},
           {'index': 2, 'name': 'allocation_type', 'type': 'hex32'},
           {'index': 3, 'name': 'protect', 'type': 'hex32'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'VirtualAllocEx',
  'category': 'memory',
  'args': [{'index': 0, 'name': 'process', 'type': 'pointer'},
           {'index': 1, 'name': 'address', 'type': 'pointer'},
           {'index': 2, 'name': 'size', 'type': 'u64'},
           {'index': 3, 'name': 'allocation_type', 'type': 'hex32'},
           {'index': 4, 'name': 'protect', 'type': 'hex32'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'VirtualProtect',
  'category': 'memory',
  'args': [{'index': 0, 'name': 'address', 'type': 'pointer'},
           {'index': 1, 'name': 'size', 'type': 'u64'},
           {'index': 2, 'name': 'new_protect', 'type': 'hex32'},
           {'index': 3, 'name': 'old_protect_ptr', 'type': 'pointer'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'VirtualProtectEx',
  'category': 'memory',
  'args': [{'index': 0, 'name': 'process', 'type': 'pointer'},
           {'index': 1, 'name': 'address', 'type': 'pointer'},
           {'index': 2, 'name': 'size', 'type': 'u64'},
           {'index': 3, 'name': 'new_protect', 'type': 'hex32'},
           {'index': 4, 'name': 'old_protect_ptr', 'type': 'pointer'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'WriteProcessMemory',
  'category': 'memory',
  'args': [{'index': 0, 'name': 'process', 'type': 'pointer'},
           {'index': 1, 'name': 'address', 'type': 'pointer'},
           {'index': 2, 'name': 'buffer', 'type': 'buffer', 'size_index': 3, 'max_len': 64},
           {'index': 3, 'name': 'size', 'type': 'u64'}],
  'capture_return': True},
 {'module': 'ntdll.dll',
  'name': 'NtWriteVirtualMemory',
  'category': 'memory',
  'args': [{'index': 0, 'name': 'process', 'type': 'pointer'},
           {'index': 1, 'name': 'base_address', 'type': 'pointer'},
           {'index': 2, 'name': 'buffer', 'type': 'buffer', 'size_index': 3, 'max_len': 64},
           {'index': 3, 'name': 'size', 'type': 'u64'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'CreateRemoteThread',
  'category': 'process',
  'args': [{'index': 0, 'name': 'process', 'type': 'pointer'},
           {'index': 2, 'name': 'stack_size', 'type': 'u64'},
           {'index': 3, 'name': 'start_address', 'type': 'pointer'},
           {'index': 4, 'name': 'parameter', 'type': 'pointer'}],
  'capture_return': True},
 {'module': 'ntdll.dll',
  'name': 'NtCreateThreadEx',
  'category': 'process',
  'args': [{'index': 0, 'name': 'thread_handle_ptr', 'type': 'pointer'},
           {'index': 3, 'name': 'process', 'type': 'pointer'},
           {'index': 4, 'name': 'start_address', 'type': 'pointer'},
           {'index': 5, 'name': 'parameter', 'type': 'pointer'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'CreateProcessA',
  'category': 'exec',
  'args': [{'index': 0, 'name': 'application', 'type': 'ansi'}, {'index': 1, 'name': 'command_line', 'type': 'ansi'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'CreateProcessW',
  'category': 'exec',
  'args': [{'index': 0, 'name': 'application', 'type': 'wide'}, {'index': 1, 'name': 'command_line', 'type': 'wide'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'WinExec',
  'category': 'exec',
  'args': [{'index': 0, 'name': 'command', 'type': 'ansi'}],
  'capture_return': True},
 {'module': 'shell32.dll',
  'name': 'ShellExecuteA',
  'category': 'exec',
  'args': [{'index': 1, 'name': 'operation', 'type': 'ansi'},
           {'index': 2, 'name': 'file', 'type': 'ansi'},
           {'index': 3, 'name': 'parameters', 'type': 'ansi'}],
  'capture_return': True},
 {'module': 'shell32.dll',
  'name': 'ShellExecuteW',
  'category': 'exec',
  'args': [{'index': 1, 'name': 'operation', 'type': 'wide'},
           {'index': 2, 'name': 'file', 'type': 'wide'},
           {'index': 3, 'name': 'parameters', 'type': 'wide'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'CreateFileA',
  'category': 'file',
  'args': [{'index': 0, 'name': 'path', 'type': 'ansi'},
           {'index': 1, 'name': 'desired_access', 'type': 'hex32'},
           {'index': 4, 'name': 'creation_disposition', 'type': 'u32'}],
  'capture_return': True},
 {'module': 'kernel32.dll',
  'name': 'CreateFileW',
  'category': 'file',
  'args': [{'index': 0, 'name': 'path', 'type': 'wide'},
           {'index': 1, 'name': 'desired_access', 'type': 'hex32'},
           {'index': 4, 'name': 'creation_disposition', 'type': 'u32'}],
  'capture_return': True},
 {'module': 'advapi32.dll',
  'name': 'RegCreateKeyExA',
  'category': 'registry',
  'args': [{'index': 1, 'name': 'subkey', 'type': 'ansi'},
           {'index': 8, 'name': 'result_handle_ptr', 'type': 'pointer'}],
  'capture_return': True},
 {'module': 'advapi32.dll',
  'name': 'RegCreateKeyExW',
  'category': 'registry',
  'args': [{'index': 1, 'name': 'subkey', 'type': 'wide'},
           {'index': 8, 'name': 'result_handle_ptr', 'type': 'pointer'}],
  'capture_return': True},
 {'module': 'advapi32.dll',
  'name': 'RegSetValueExA',
  'category': 'registry',
  'args': [{'index': 1, 'name': 'value_name', 'type': 'ansi'},
           {'index': 3, 'name': 'type', 'type': 'u32'},
           {'index': 5, 'name': 'size', 'type': 'u32'}],
  'capture_return': True},
 {'module': 'advapi32.dll',
  'name': 'RegSetValueExW',
  'category': 'registry',
  'args': [{'index': 1, 'name': 'value_name', 'type': 'wide'},
           {'index': 3, 'name': 'type', 'type': 'u32'},
           {'index': 5, 'name': 'size', 'type': 'u32'}],
  'capture_return': True},
 {'module': 'winhttp.dll',
  'name': 'WinHttpOpen',
  'category': 'network',
  'args': [{'index': 0, 'name': 'user_agent', 'type': 'wide'}],
  'capture_return': True},
 {'module': 'winhttp.dll',
  'name': 'WinHttpConnect',
  'category': 'network',
  'args': [{'index': 1, 'name': 'server', 'type': 'wide'}, {'index': 2, 'name': 'port', 'type': 'u32'}],
  'capture_return': True},
 {'module': 'winhttp.dll',
  'name': 'WinHttpOpenRequest',
  'category': 'network',
  'args': [{'index': 1, 'name': 'verb', 'type': 'wide'}, {'index': 2, 'name': 'object_name', 'type': 'wide'}],
  'capture_return': True},
 {'module': 'winhttp.dll',
  'name': 'WinHttpSendRequest',
  'category': 'network',
  'args': [{'index': 1, 'name': 'headers', 'type': 'wide'},
           {'index': 3, 'name': 'optional', 'type': 'buffer', 'size_index': 4, 'max_len': 96},
           {'index': 4, 'name': 'optional_length', 'type': 'u32'}],
  'capture_return': True},
 {'module': 'wininet.dll',
  'name': 'InternetConnectA',
  'category': 'network',
  'args': [{'index': 1, 'name': 'server', 'type': 'ansi'}, {'index': 2, 'name': 'port', 'type': 'u32'}],
  'capture_return': True},
 {'module': 'wininet.dll',
  'name': 'InternetConnectW',
  'category': 'network',
  'args': [{'index': 1, 'name': 'server', 'type': 'wide'}, {'index': 2, 'name': 'port', 'type': 'u32'}],
  'capture_return': True},
 {'module': 'urlmon.dll',
  'name': 'URLDownloadToFileA',
  'category': 'network',
  'args': [{'index': 1, 'name': 'url', 'type': 'ansi'}, {'index': 2, 'name': 'file', 'type': 'ansi'}],
  'capture_return': True},
 {'module': 'urlmon.dll',
  'name': 'URLDownloadToFileW',
  'category': 'network',
  'args': [{'index': 1, 'name': 'url', 'type': 'wide'}, {'index': 2, 'name': 'file', 'type': 'wide'}],
  'capture_return': True},
 {'module': 'ws2_32.dll',
  'name': 'connect',
  'category': 'network',
  'args': [{'index': 0, 'name': 'socket', 'type': 'u32'},
           {'index': 1, 'name': 'address', 'type': 'sockaddr'},
           {'index': 2, 'name': 'address_length', 'type': 'u32'}],
  'capture_return': True},
 {'module': 'ws2_32.dll',
  'name': 'WSAConnect',
  'category': 'network',
  'args': [{'index': 0, 'name': 'socket', 'type': 'u32'},
           {'index': 1, 'name': 'address', 'type': 'sockaddr'},
           {'index': 2, 'name': 'address_length', 'type': 'u32'}],
  'capture_return': True},
 {'module': 'ws2_32.dll',
  'name': 'send',
  'category': 'network',
  'args': [{'index': 0, 'name': 'socket', 'type': 'u32'},
           {'index': 1, 'name': 'buffer', 'type': 'buffer', 'size_index': 2, 'max_len': 96},
           {'index': 2, 'name': 'length', 'type': 'u32'},
           {'index': 3, 'name': 'flags', 'type': 'hex32'}],
  'capture_return': True},
 {'module': 'ws2_32.dll',
  'name': 'recv',
  'category': 'network',
  'args': [{'index': 0, 'name': 'socket', 'type': 'u32'},
           {'index': 1, 'name': 'buffer', 'type': 'pointer'},
           {'index': 2, 'name': 'length', 'type': 'u32'},
           {'index': 3, 'name': 'flags', 'type': 'hex32'}],
  'capture_return': True},
 {'module': 'ws2_32.dll',
  'name': 'getaddrinfo',
  'category': 'network',
  'args': [{'index': 0, 'name': 'node', 'type': 'ansi'}, {'index': 1, 'name': 'service', 'type': 'ansi'}],
  'capture_return': True})


def frida_install_guide() -> Dict[str, Any]:
    guide = "\n".join(
        [
            "Frida dynamic tracing installation guide",
            "",
            "1. Install Python 3.x if it is not already available.",
            "2. Install Frida CLI tools and Python bindings:",
            "   python -m pip install --upgrade frida-tools",
            "3. Verify the CLI:",
            "   frida --version",
            "4. Verify the Python package:",
            "   python -c \"import frida; print(frida.__version__)\"",
            "5. Optional reference:",
            f"   {FRIDA_DOCS_URL}",
            "6. Example usage with this project:",
            "   python -m reverse_analyzer analyze .\\samples\\app.exe --out .\\reports\\app --dynamic",
            "7. Optional trace duration override:",
            "   python -m reverse_analyzer analyze .\\samples\\app.exe --out .\\reports\\app --dynamic --dynamic-duration 15",
            "8. Optional Frida hook profile selection:",
            "   python -m reverse_analyzer analyze .\\samples\\app.exe --out .\\reports\\app --dynamic --dynamic-profile unpacking",
        ]
    )
    return {"status": "guide", "guide": guide}


def frida_hook_profiles() -> Dict[str, Any]:
    """Return available built-in Frida hook profiles."""

    return {
        name: {
            "description": str(profile.get("description") or ""),
            "hook_count": len(frida_hooks_for_profile(name)),
        }
        for name, profile in FRIDA_HOOK_PROFILES.items()
    }


def frida_hooks_for_profile(profile: str = "behavior") -> list[Dict[str, Any]]:
    """Select a built-in hook plan by reverse-analysis use case."""

    profile_name = str(profile or "behavior").lower()
    if profile_name not in FRIDA_HOOK_PROFILES:
        raise ValueError(f"unknown Frida hook profile: {profile}. Available: {', '.join(sorted(FRIDA_HOOK_PROFILES))}")
    rule = FRIDA_HOOK_PROFILES[profile_name]
    hooks = [dict(item) for item in DEFAULT_HOOKS]
    if profile_name == "behavior":
        return hooks

    names = {str(item).lower() for item in rule.get("names") or set()}
    categories = {str(item).lower() for item in rule.get("categories") or set()}
    selected = [
        item
        for item in hooks
        if (names and str(item.get("name") or "").lower() in names)
        or (categories and str(item.get("category") or "").lower() in categories)
    ]
    return selected


def frida_check() -> Dict[str, Any]:
    try:
        frida = _load_frida()
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "unavailable",
            "dependency": "frida",
            "error": str(exc),
            "setup_hint": "Install Frida with `python -m pip install --upgrade frida-tools` and verify with `frida --version`.",
            "install_guide": "Run: python -m reverse_analyzer --install-guide frida",
            "docs_url": FRIDA_DOCS_URL,
        }

    cli_path = shutil.which("frida")
    trace_cli = shutil.which("frida-trace")
    return {
        "status": "ok",
        "python_binding": getattr(frida, "__file__", None),
        "version": getattr(frida, "__version__", None),
        "cli_path": cli_path,
        "trace_cli": trace_cli,
        "docs_url": FRIDA_DOCS_URL,
    }


def frida_trace(
    path: str | Path,
    out_dir: str | Path,
    *,
    duration: float = DEFAULT_DURATION,
    target_args: Optional[Iterable[str]] = None,
    attach_pid: Optional[int] = None,
    hooks: Optional[Iterable[Mapping[str, Any]]] = None,
    hook_profile: str = "behavior",
    kill_on_exit: bool = True,
) -> ToolResult | Dict[str, Any]:
    sample = Path(path)
    if attach_pid is None and not sample.is_file():
        raise FileNotFoundError(str(sample))

    check = frida_check()
    if check.get("status") != "ok":
        return ToolResult(
            tool="frida_trace",
            status="unavailable",
            error=check.get("error"),
            data={
                "status": "unavailable",
                "setup_hint": check.get("setup_hint"),
                "install_guide": check.get("install_guide"),
                "docs_url": check.get("docs_url"),
                "artifacts": [],
            },
        )

    frida = _load_frida()
    output_dir = Path(out_dir) / "dynamic" / "frida"
    output_dir.mkdir(parents=True, exist_ok=True)
    agent_path = output_dir / "agent.js"
    events_path = output_dir / "events.jsonl"
    trace_path = output_dir / "trace.json"
    summary_path = output_dir / "summary.json"

    hook_plan = [dict(item) for item in hooks] if hooks is not None else frida_hooks_for_profile(hook_profile)
    agent_source = _render_agent(hook_plan)
    agent_path.write_text(agent_source, encoding="utf-8")

    events: list[Dict[str, Any]] = []
    process_info: Dict[str, Any] = {}
    spawned_pid: Optional[int] = None
    device = None
    session = None
    script = None
    started_at = time.time()
    mode = "attach" if attach_pid is not None else "spawn"
    argv = [str(sample), *(str(item) for item in (target_args or []))]
    error_message: Optional[str] = None

    try:
        device = frida.get_local_device()
        if attach_pid is not None:
            session = device.attach(int(attach_pid))
            process_info["attached_pid"] = int(attach_pid)
        else:
            spawned_pid = int(device.spawn(argv))
            process_info["spawned_pid"] = spawned_pid
            process_info["argv"] = argv
            session = device.attach(spawned_pid)

        script = session.create_script(agent_source)

        def on_message(message: Mapping[str, Any], data: Any) -> None:
            record: Dict[str, Any] = {"message_type": message.get("type")}
            if message.get("type") == "send":
                payload = message.get("payload")
                if isinstance(payload, Mapping):
                    record.update({str(k): v for k, v in payload.items()})
                    if payload.get("event") == "ready":
                        ready_process = payload.get("process") or {}
                        if isinstance(ready_process, Mapping):
                            process_info.update({str(k): v for k, v in ready_process.items()})
                        if payload.get("hook_count") is not None:
                            process_info["hook_count"] = payload.get("hook_count")
                else:
                    record["payload"] = payload
            elif message.get("type") == "error":
                record["description"] = message.get("description")
                record["stack"] = message.get("stack")
            if data is not None:
                record["data"] = data
            events.append(_json_safe(record))

        script.on("message", on_message)
        script.load()
        if spawned_pid is not None:
            device.resume(spawned_pid)
        time.sleep(max(0.1, float(duration)))
    except Exception as exc:  # noqa: BLE001
        error_message = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            if script is not None:
                script.unload()
        except Exception:
            pass
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass
        if spawned_pid is not None and kill_on_exit and device is not None:
            try:
                device.kill(spawned_pid)
            except Exception:
                pass

    duration_seconds = round(time.time() - started_at, 3)
    events_path.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False, sort_keys=True) for item in events) + ("\n" if events else ""),
        encoding="utf-8",
    )

    calls = [item for item in events if item.get("event") == "call"]
    returns = [item for item in events if item.get("event") == "return"]
    installed_hooks = [item for item in events if item.get("event") == "hook-installed"]
    missing_hooks = [item for item in events if item.get("event") == "hook-missing"]
    api_counts = Counter(str(item.get("name")) for item in calls if item.get("name"))
    category_counts = Counter(str(item.get("category")) for item in calls if item.get("category"))
    summary = {
        "status": "failed" if error_message else "ok",
        "mode": mode,
        "duration_seconds": duration_seconds,
        "hook_profile": "custom" if hooks is not None else hook_profile,
        "planned_hook_count": len(hook_plan),
        "event_count": len(calls),
        "return_event_count": len(returns),
        "installed_hook_count": len(installed_hooks),
        "missing_hook_count": len(missing_hooks),
        "api_counts": dict(api_counts),
        "category_counts": dict(category_counts),
        "process": process_info,
        "error": error_message,
    }
    trace_payload = {
        "status": summary["status"],
        "mode": mode,
        "process": process_info,
        "events": calls,
        "return_events": returns[:200],
        "installed_hooks": installed_hooks,
        "missing_hooks": missing_hooks,
        "api_counts": dict(api_counts),
        "category_counts": dict(category_counts),
        "duration_seconds": duration_seconds,
        "hook_profile": "custom" if hooks is not None else hook_profile,
        "planned_hook_count": len(hook_plan),
        "return_event_count": len(returns),
        "agent_path": str(agent_path),
        "error": error_message,
    }
    trace_path.write_text(json.dumps(trace_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    artifacts = [
        {"name": "agent.js", "path": str(agent_path), "kind": "script"},
        {"name": "events.jsonl", "path": str(events_path), "kind": "trace"},
        {"name": "trace.json", "path": str(trace_path), "kind": "trace"},
        {"name": "summary.json", "path": str(summary_path), "kind": "analysis"},
    ]

    if error_message:
        return ToolResult(
            tool="frida_trace",
            status="failed",
            error=error_message,
            data={
                **trace_payload,
                "output_dir": str(output_dir),
                "artifacts": artifacts,
                "setup_hint": "Verify the sample can be spawned locally and that Frida can attach to the target process.",
            },
        )

    return {
        "status": "ok",
        "backend": "frida",
        "output_dir": str(output_dir),
        "mode": mode,
        "duration_seconds": duration_seconds,
        "hook_profile": "custom" if hooks is not None else hook_profile,
        "planned_hook_count": len(hook_plan),
        "process": process_info,
        "event_count": len(calls),
        "return_event_count": len(returns),
        "installed_hook_count": len(installed_hooks),
        "missing_hook_count": len(missing_hooks),
        "api_counts": dict(api_counts),
        "category_counts": dict(category_counts),
        "events": calls,
        "return_events": returns[:50],
        "installed_hooks": installed_hooks,
        "missing_hooks": missing_hooks,
        "artifacts": artifacts,
        "docs_url": FRIDA_DOCS_URL,
    }


def _load_frida() -> Any:
    return importlib.import_module("frida")


def _render_agent(hooks: Iterable[Mapping[str, Any]]) -> str:
    hook_json = json.dumps([_json_safe(dict(item)) for item in hooks], ensure_ascii=False)
    return f"""
'use strict';

const HOOKS = {hook_json};

function safeReadAnsi(ptrValue) {{
  if (ptrValue.isNull()) return null;
  try {{
    return Memory.readUtf8String(ptrValue);
  }} catch (e) {{
    return ptrValue.toString();
  }}
}}

function safeReadWide(ptrValue) {{
  if (ptrValue.isNull()) return null;
  try {{
    return Memory.readUtf16String(ptrValue);
  }} catch (e) {{
    return ptrValue.toString();
  }}
}}

function safeNumber(ptrValue) {{
  try {{
    if (Process.pointerSize === 8 && ptr(ptrValue).toUInt64 !== undefined) {{
      return ptr(ptrValue).toUInt64().toString();
    }}
    return ptr(ptrValue).toUInt32();
  }} catch (e) {{
    return ptrValue.toString();
  }}
}}

function safeHex(ptrValue) {{
  try {{
    return '0x' + ptr(ptrValue).toUInt32().toString(16);
  }} catch (e) {{
    return ptrValue.toString();
  }}
}}

function safePointer(ptrValue) {{
  try {{
    return ptr(ptrValue).toString();
  }} catch (e) {{
    return String(ptrValue);
  }}
}}

function safeAnsiOrOrdinal(ptrValue) {{
  try {{
    const numeric = ptr(ptrValue).toUInt32();
    if (numeric > 0 && numeric < 0x10000) {{
      return '#' + numeric.toString();
    }}
  }} catch (e) {{}}
  return safeReadAnsi(ptrValue);
}}

function safeReadBuffer(ptrValue, lengthValue, maxLen) {{
  if (ptrValue.isNull()) return null;
  let requested = 0;
  try {{
    requested = ptr(lengthValue).toUInt32();
  }} catch (e) {{
    requested = maxLen || 64;
  }}
  const limit = Math.max(0, Math.min(requested, maxLen || 64));
  if (limit === 0) {{
    return {{ length: requested, truncated: requested > 0, hex: '', ascii: '' }};
  }}
  try {{
    const bytes = new Uint8Array(Memory.readByteArray(ptrValue, limit));
    let hex = '';
    let ascii = '';
    for (let i = 0; i < bytes.length; i++) {{
      const b = bytes[i];
      hex += ('0' + b.toString(16)).slice(-2);
      ascii += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.';
    }}
    return {{ length: requested, captured: bytes.length, truncated: requested > bytes.length, hex: hex, ascii: ascii }};
  }} catch (e) {{
    return {{ length: requested, error: String(e), pointer: safePointer(ptrValue) }};
  }}
}}

function safeReadSockaddr(ptrValue) {{
  if (ptrValue.isNull()) return null;
  try {{
    const family = Memory.readU16(ptrValue);
    if (family === 2) {{
      const port = (Memory.readU8(ptrValue.add(2)) << 8) + Memory.readU8(ptrValue.add(3));
      const ip = [
        Memory.readU8(ptrValue.add(4)),
        Memory.readU8(ptrValue.add(5)),
        Memory.readU8(ptrValue.add(6)),
        Memory.readU8(ptrValue.add(7))
      ].join('.');
      return {{ family: 'AF_INET', ip: ip, port: port }};
    }}
    if (family === 23) {{
      const port6 = (Memory.readU8(ptrValue.add(2)) << 8) + Memory.readU8(ptrValue.add(3));
      const parts = [];
      for (let i = 0; i < 8; i++) {{
        const word = (Memory.readU8(ptrValue.add(8 + i * 2)) << 8) + Memory.readU8(ptrValue.add(9 + i * 2));
        parts.push(word.toString(16));
      }}
      return {{ family: 'AF_INET6', ip: parts.join(':'), port: port6 }};
    }}
    return {{ family: family, pointer: safePointer(ptrValue) }};
  }} catch (e) {{
    return {{ error: String(e), pointer: safePointer(ptrValue) }};
  }}
}}

function readArg(spec, args) {{
  const argIndex = (spec.index === undefined || spec.index === null) ? 0 : spec.index;
  const argValue = args[argIndex];
  const kind = spec.type || 'pointer';
  if (kind === 'ansi') return safeReadAnsi(argValue);
  if (kind === 'ansi_or_ordinal') return safeAnsiOrOrdinal(argValue);
  if (kind === 'wide') return safeReadWide(argValue);
  if (kind === 'u32' || kind === 'u64') return safeNumber(argValue);
  if (kind === 'hex32') return safeHex(argValue);
  if (kind === 'buffer') {{
    const sizeIndex = (spec.size_index === undefined || spec.size_index === null) ? (argIndex + 1) : spec.size_index;
    return safeReadBuffer(argValue, args[sizeIndex], spec.max_len || 64);
  }}
  if (kind === 'sockaddr') return safeReadSockaddr(argValue);
  return safePointer(argValue);
}}

function moduleSnapshot(limit) {{
  try {{
    return Process.enumerateModulesSync().slice(0, limit || 80).map(function (m) {{
      return {{ name: m.name, base: m.base.toString(), size: m.size, path: m.path }};
    }});
  }} catch (e) {{
    return [{{ error: String(e) }}];
  }}
}}

HOOKS.forEach(function (hook) {{
  const address = Module.findExportByName(hook.module, hook.name);
  if (address === null) {{
    send({{ event: 'hook-missing', module: hook.module, name: hook.name, category: hook.category }});
    return;
  }}

  send({{ event: 'hook-installed', module: hook.module, name: hook.name, category: hook.category, address: address.toString() }});

  Interceptor.attach(address, {{
    onEnter(args) {{
      const params = {{}};
      (hook.args || []).forEach(function (spec, index) {{
        params[spec.name || ('arg' + index)] = readArg(spec, args);
      }});
      this.params = params;
      send({{
        event: 'call',
        ts: Date.now(),
        module: hook.module,
        name: hook.name,
        category: hook.category,
        thread_id: Process.getCurrentThreadId(),
        params: params
      }});
    }},
    onLeave(retval) {{
      if (!hook.capture_return) return;
      send({{
        event: 'return',
        ts: Date.now(),
        module: hook.module,
        name: hook.name,
        category: hook.category,
        thread_id: Process.getCurrentThreadId(),
        return_value: safePointer(retval),
        params: this.params || {{}}
      }});
    }}
  }});
}});

send({{
  event: 'ready',
  process: {{
    id: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    modules: moduleSnapshot(80)
  }},
  hook_count: HOOKS.length
}});
"""


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return value
