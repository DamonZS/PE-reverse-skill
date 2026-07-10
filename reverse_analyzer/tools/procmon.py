"""Optional Microsoft Procmon-backed behavioral capture backend."""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from .executor import ToolResult


PROCMON_DOCS_URL = "https://learn.microsoft.com/en-us/sysinternals/downloads/procmon"
DEFAULT_DURATION = 10.0
DEFAULT_PROC_NAMES = ("procmon64.exe", "procmon.exe", "procmon64a.exe")


_OPERATION_CATEGORIES = (
    ("registry", ("Reg",)),
    ("file", ("CreateFile", "ReadFile", "WriteFile", "Query", "Set", "CloseFile", "CreateFileMapping")),
    ("process", ("Process", "Thread", "Load Image")),
    ("network", ("TCP", "UDP")),
)


def procmon_install_guide() -> Dict[str, Any]:
    guide = "\n".join(
        [
            "Procmon behavioral capture installation guide",
            "",
            "1. Download Process Monitor from Microsoft Sysinternals:",
            f"   {PROCMON_DOCS_URL}",
            "2. Extract Procmon.exe or Procmon64.exe into a directory on PATH,",
            "   or pass --procmon-path C:\\Tools\\Procmon64.exe.",
            "3. Run once interactively if your environment requires accepting the EULA,",
            "   or let this tool pass /AcceptEula for non-interactive runs.",
            "4. Example usage with this project:",
            "   python -m reverse_analyzer analyze .\\samples\\app.exe --out .\\reports\\app --dynamic --dynamic-backend procmon",
            "5. Combine Frida API tracing and Procmon OS behavior capture:",
            "   python -m reverse_analyzer analyze .\\samples\\app.exe --out .\\reports\\app --dynamic --dynamic-backend all",
        ]
    )
    return {"status": "guide", "guide": guide, "docs_url": PROCMON_DOCS_URL}


def procmon_check(procmon_path: str | Path | None = None) -> Dict[str, Any]:
    resolved = _find_procmon(procmon_path)
    if resolved is None:
        return {
            "status": "unavailable",
            "dependency": "procmon",
            "error": "Process Monitor executable was not found on PATH.",
            "setup_hint": "Install Microsoft Sysinternals Procmon and add Procmon64.exe/Procmon.exe to PATH, or pass --procmon-path.",
            "install_guide": "Run: python -m reverse_analyzer --install-guide procmon",
            "docs_url": PROCMON_DOCS_URL,
        }
    return {"status": "ok", "path": str(resolved), "docs_url": PROCMON_DOCS_URL}


def procmon_trace(
    path: str | Path,
    out_dir: str | Path,
    *,
    duration: float = DEFAULT_DURATION,
    target_args: Optional[Iterable[str]] = None,
    attach_pid: Optional[int] = None,
    procmon_path: str | Path | None = None,
    convert_csv: bool = True,
    kill_on_exit: bool = True,
) -> ToolResult | Dict[str, Any]:
    sample = Path(path)
    if attach_pid is None and not sample.is_file():
        raise FileNotFoundError(str(sample))

    check = procmon_check(procmon_path)
    if check.get("status") != "ok":
        return ToolResult(
            tool="procmon_trace",
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

    executable = str(check["path"])
    output_dir = Path(out_dir) / "dynamic" / "procmon"
    output_dir.mkdir(parents=True, exist_ok=True)
    pml_path = output_dir / "trace.pml"
    csv_path = output_dir / "events.csv"
    summary_path = output_dir / "summary.json"
    manifest_path = output_dir / "manifest.json"

    proc: subprocess.Popen[Any] | None = None
    started_at = time.time()
    argv = [str(sample), *(str(item) for item in (target_args or []))]
    error_message: str | None = None

    try:
        _run_procmon([executable, "/AcceptEula", "/Quiet", "/Minimized", "/BackingFile", str(pml_path)], timeout=20)
        if attach_pid is None:
            proc = subprocess.Popen(argv, cwd=str(sample.parent) if sample.parent else None)
        time.sleep(max(0.1, float(duration)))
    except Exception as exc:  # noqa: BLE001
        error_message = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            _run_procmon([executable, "/Terminate"], timeout=30)
        except Exception as exc:  # noqa: BLE001
            if error_message is None:
                error_message = f"terminate_failed:{type(exc).__name__}: {exc}"
        if proc is not None and kill_on_exit and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    conversion_error: str | None = None
    if convert_csv and pml_path.exists():
        try:
            _run_procmon([executable, "/AcceptEula", "/OpenLog", str(pml_path), "/SaveAs", str(csv_path)], timeout=120)
        except Exception as exc:  # noqa: BLE001
            conversion_error = f"{type(exc).__name__}: {exc}"

    parsed = _parse_csv(csv_path, sample_name=sample.name if attach_pid is None else None) if csv_path.exists() else {}
    duration_seconds = round(time.time() - started_at, 3)
    summary = {
        "status": "failed" if error_message else "ok",
        "backend": "procmon",
        "mode": "attach" if attach_pid is not None else "spawn",
        "duration_seconds": duration_seconds,
        "procmon_path": executable,
        "pml_path": str(pml_path),
        "csv_path": str(csv_path) if csv_path.exists() else None,
        "event_count": parsed.get("event_count", 0),
        "operation_counts": parsed.get("operation_counts", {}),
        "category_counts": parsed.get("category_counts", {}),
        "top_paths": parsed.get("top_paths", []),
        "sample_events": parsed.get("sample_events", []),
        "process": {"argv": argv, "pid": proc.pid if proc is not None else attach_pid},
        "error": error_message,
        "conversion_error": conversion_error,
        "docs_url": PROCMON_DOCS_URL,
    }
    artifacts = [
        {"name": "trace.pml", "path": str(pml_path), "kind": "trace"},
        {"name": "summary.json", "path": str(summary_path), "kind": "analysis"},
        {"name": "manifest.json", "path": str(manifest_path), "kind": "manifest"},
    ]
    if csv_path.exists():
        artifacts.insert(1, {"name": "events.csv", "path": str(csv_path), "kind": "trace"})
    summary["artifacts"] = artifacts

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest_path.write_text(
        json.dumps(
            {
                "tool": "procmon_trace",
                "command_model": "Procmon /BackingFile capture followed by optional /OpenLog /SaveAs CSV conversion",
                "artifacts": artifacts,
                "docs_url": PROCMON_DOCS_URL,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    if error_message:
        return ToolResult(
            tool="procmon_trace",
            status="failed",
            error=error_message,
            data={
                **summary,
                "output_dir": str(output_dir),
                "setup_hint": "Verify Procmon can run elevated if your environment requires kernel event capture privileges.",
            },
        )

    return {**summary, "output_dir": str(output_dir)}


def _find_procmon(procmon_path: str | Path | None = None) -> Path | None:
    if procmon_path:
        candidate = Path(procmon_path)
        return candidate.resolve() if candidate.is_file() else None
    for name in DEFAULT_PROC_NAMES:
        found = shutil.which(name)
        if found:
            return Path(found).resolve()
    return None


def _run_procmon(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, shell=False, check=False)
    if completed.returncode not in (0, 1):
        raise RuntimeError(f"Procmon command failed ({completed.returncode}): {completed.stderr or completed.stdout}")
    return completed


def _parse_csv(path: Path, *, sample_name: str | None = None, limit: int = 20000) -> Dict[str, Any]:
    operation_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    path_counts: Counter[str] = Counter()
    sample_events: list[Dict[str, Any]] = []
    event_count = 0

    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if event_count >= limit:
                break
            process_name = row.get("Process Name") or row.get("Process") or ""
            if sample_name and process_name and process_name.lower() != sample_name.lower():
                continue
            event_count += 1
            operation = row.get("Operation") or "unknown"
            target_path = row.get("Path") or ""
            result = row.get("Result") or ""
            operation_counts[operation] += 1
            if target_path:
                path_counts[target_path] += 1
            category = _category_for_operation(operation)
            category_counts[category] += 1
            if len(sample_events) < 25:
                sample_events.append(
                    {
                        "process": process_name,
                        "operation": operation,
                        "category": category,
                        "path": target_path,
                        "result": result,
                        "detail": row.get("Detail") or "",
                    }
                )

    return {
        "event_count": event_count,
        "operation_counts": dict(operation_counts.most_common(25)),
        "category_counts": dict(category_counts),
        "top_paths": [{"path": name, "count": count} for name, count in path_counts.most_common(15)],
        "sample_events": sample_events,
    }


def _category_for_operation(operation: str) -> str:
    for category, prefixes in _OPERATION_CATEGORIES:
        if any(operation.startswith(prefix) for prefix in prefixes):
            return category
    return "other"
