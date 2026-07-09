"""Ghidra Headless integration helpers.

The functions in this module are intentionally safe to import on machines that
have no Ghidra installation.  Detection returns structured ``unavailable``
results and decompilation degrades gracefully instead of breaking the normal
analysis pipeline.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
from typing import Any, Dict, Iterable, List, Optional

from .executor import ToolResult

GHIDRA_INSTALL_GUIDE = """Ghidra Headless installation guide (Windows PowerShell)

1. Install Java JDK 21:
   winget install EclipseAdoptium.Temurin.21.JDK

2. Verify Java:
   java -version

3. Download Ghidra from the official releases page:
   https://github.com/NationalSecurityAgency/ghidra/releases/latest

4. Extract the ZIP to a stable location, for example:
   C:\\Tools\\ghidra_<version>_PUBLIC

5. Configure user environment variables, replacing the path with your actual folder:
   $ghidra = "C:\\Tools\\ghidra_<version>_PUBLIC"
   [Environment]::SetEnvironmentVariable("GHIDRA_HOME", $ghidra, "User")
   [Environment]::SetEnvironmentVariable("GHIDRA_HEADLESS", "$ghidra\\support\\analyzeHeadless.bat", "User")

6. Open a new PowerShell window and verify:
   Test-Path $env:GHIDRA_HEADLESS
   & $env:GHIDRA_HEADLESS
""".strip()

_SETUP_HINT = "Run: python -m reverse_analyzer --install-guide ghidra"


def ghidra_install_guide() -> Dict[str, Any]:
    """Return a printable Ghidra Headless installation guide."""

    return {
        "tool": "ghidra",
        "status": "guide",
        "title": "Ghidra Headless installation guide",
        "guide": GHIDRA_INSTALL_GUIDE,
        "setup_hint": _SETUP_HINT,
    }


def ghidra_check(ghidra_home: str | os.PathLike[str] | None = None) -> Dict[str, Any]:
    """Discover a usable Ghidra ``analyzeHeadless`` executable.

    Discovery order:
    1. Explicit ``ghidra_home`` argument.
    2. ``GHIDRA_HEADLESS`` environment variable.
    3. ``GHIDRA_HOME/support/analyzeHeadless(.bat)``.
    4. Common Windows installation directories.
    """

    checked: List[str] = []

    def check_headless(candidate: Path, source: str) -> Optional[Dict[str, Any]]:
        checked.append(str(candidate))
        if candidate.is_file():
            return _available(candidate, source, checked)
        return None

    def check_home(home: str | os.PathLike[str] | None, source: str) -> Optional[Dict[str, Any]]:
        if not home:
            return None
        root = Path(home).expanduser()
        for candidate in _headless_candidates(root):
            found = check_headless(candidate, source)
            if found:
                return found
        return None

    found = check_home(ghidra_home, "argument:ghidra_home")
    if found:
        return found

    env_headless = os.environ.get("GHIDRA_HEADLESS")
    if env_headless:
        found = check_headless(Path(env_headless).expanduser(), "env:GHIDRA_HEADLESS")
        if found:
            return found

    found = check_home(os.environ.get("GHIDRA_HOME"), "env:GHIDRA_HOME")
    if found:
        return found

    for root in _common_ghidra_roots():
        found = check_home(root, "common-path")
        if found:
            return found

    return {
        "tool": "ghidra",
        "status": "unavailable",
        "error": "Ghidra Headless is not configured or was not found.",
        "setup_hint": _SETUP_HINT,
        "checked_paths": checked,
        "install_guide": GHIDRA_INSTALL_GUIDE,
    }


def ghidra_decompile(
    path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    ghidra_home: str | os.PathLike[str] | None = None,
    timeout: int | float = 900,
) -> ToolResult | Dict[str, Any]:
    """Run Ghidra Headless and export structured decompiler artifacts."""

    sample = Path(path)
    if not sample.is_file():
        raise FileNotFoundError(str(sample))

    check = ghidra_check(ghidra_home)
    ghidra_out = Path(out_dir) / "decompiled" / "ghidra"
    ghidra_out.mkdir(parents=True, exist_ok=True)

    if check.get("status") != "ok":
        return ToolResult(
            tool="ghidra_decompile",
            status="unavailable",
            error=str(check.get("error") or "Ghidra Headless unavailable"),
            data={
                "status": "unavailable",
                "path": str(sample),
                "setup_hint": check.get("setup_hint", _SETUP_HINT),
                "install_guide": check.get("install_guide", GHIDRA_INSTALL_GUIDE),
                "checked_paths": check.get("checked_paths", []),
                "artifacts": [],
            },
        )

    project_dir = ghidra_out / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = _safe_project_name(sample)
    script_dir = Path(__file__).resolve().parent / "ghidra_scripts"
    log_path = ghidra_out / "ghidra.log"
    command = [
        str(check["headless_path"]),
        str(project_dir),
        project_name,
        "-import",
        str(sample),
        "-scriptPath",
        str(script_dir),
        "-postScript",
        "ExportDecompiler.py",
        str(ghidra_out),
        "-deleteProject",
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=float(timeout),
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log_path.write_text((exc.stdout or "") + "\n" + (exc.stderr or ""), encoding="utf-8")
        return ToolResult(
            tool="ghidra_decompile",
            status="failed",
            error=f"Ghidra Headless timed out after {timeout} seconds",
            data={"status": "failed", "path": str(sample), "artifacts": [_artifact("ghidra.log", log_path)]},
        )

    log_path.write_text((completed.stdout or "") + "\n" + (completed.stderr or ""), encoding="utf-8")
    artifacts = _collect_artifacts(ghidra_out)
    functions = _read_json(ghidra_out / "functions.json", default=[])
    call_graph = _read_json(ghidra_out / "call_graph.json", default={"nodes": [], "edges": []})
    summary = _read_json(ghidra_out / "summary.json", default={})

    status = "ok" if completed.returncode == 0 else "failed"
    data = {
        "status": status,
        "path": str(sample),
        "headless_path": str(check["headless_path"]),
        "ghidra_home": check.get("ghidra_home"),
        "project_dir": str(project_dir),
        "output_dir": str(ghidra_out),
        "returncode": completed.returncode,
        "artifacts": artifacts,
        "functions": functions,
        "function_count": len(functions) if isinstance(functions, list) else 0,
        "call_graph": call_graph,
        "summary": summary,
    }
    if completed.returncode != 0:
        return ToolResult(
            tool="ghidra_decompile",
            status="failed",
            error=f"Ghidra Headless exited with code {completed.returncode}; see ghidra.log",
            data=data,
        )
    return data


def _available(headless: Path, source: str, checked: Iterable[str]) -> Dict[str, Any]:
    home = headless.parent.parent if headless.parent.name.lower() == "support" else headless.parent
    return {
        "tool": "ghidra",
        "status": "ok",
        "source": source,
        "headless_path": str(headless),
        "ghidra_home": str(home),
        "checked_paths": list(checked),
    }


def _headless_candidates(root: Path) -> list[Path]:
    if root.name.lower().startswith("analyzeheadless"):
        return [root]
    names = ["analyzeHeadless.bat"] if platform.system().lower() == "windows" else ["analyzeHeadless"]
    # Check both names on every platform so tests and cross-platform archives are easy to use.
    for name in ("analyzeHeadless.bat", "analyzeHeadless"):
        if name not in names:
            names.append(name)
    return [root / "support" / name for name in names]


def _common_ghidra_roots() -> list[Path]:
    roots: list[Path] = []
    for pattern in (r"C:\Tools\ghidra*", r"C:\Program Files\Ghidra\ghidra*", r"D:\Tools\ghidra*"):
        roots.extend(Path().glob(pattern) if not pattern[1:3] == ":\\" else _glob_windows(pattern))
    return [root for root in roots if root.is_dir()]


def _glob_windows(pattern: str) -> list[Path]:
    import glob

    return [Path(item) for item in glob.glob(pattern)]


def _safe_project_name(sample: Path) -> str:
    return "reverse_analyzer_" + "".join(ch if ch.isalnum() else "_" for ch in sample.stem)[:48]


def _collect_artifacts(root: Path) -> list[Dict[str, Any]]:
    names = [
        "functions.json",
        "call_graph.json",
        "strings_xrefs.json",
        "imports_xrefs.json",
        "summary.json",
        "ghidra.log",
    ]
    artifacts = [_artifact(name, root / name) for name in names if (root / name).exists()]
    for subdir, kind in (("pseudocode", "pseudocode"), ("disassembly", "disassembly")):
        directory = root / subdir
        if directory.is_dir():
            for item in sorted(directory.iterdir()):
                if item.is_file():
                    artifacts.append(_artifact(item.name, item, kind=kind))
    return artifacts


def _artifact(name: str, path: Path, kind: str = "decompiler") -> Dict[str, Any]:
    return {"name": name, "path": str(path), "kind": kind}


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default
