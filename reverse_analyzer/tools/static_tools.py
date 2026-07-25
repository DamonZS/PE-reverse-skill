"""Built-in local static-analysis tools.

These tools avoid network access and active exploitation. Optional reverse
engineering dependencies are imported lazily so missing packages degrade into
``unavailable`` results instead of import-time failures.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Dict, Iterable, List

from .executor import ToolExecutor, ToolResult
from .frida import frida_check, frida_hook_profiles, frida_install_guide, frida_trace
from .patch import (
    android_elf_patch_plan,
    android_elf_patch_verify,
    binary_patch_apply_plan,
    binary_patch_rollback_plan,
    dll_proxy_generate,
    validate_patch_plan,
)
from .procmon import procmon_check, procmon_install_guide, procmon_trace
from .ghidra import ghidra_check, ghidra_decompile, ghidra_install_guide
from .gui import (
    gui_fingerprint,
    gui_resource_extract,
    gui_runtime_probe,
    gui_strategy_select,
    gui_visual_parse,
    gui_visual_regression,
    gui_world_projection,
    reconstruct_gui_project,
)
from .gui_evidence import build_gui_evidence_graph
from .behavior_graph import build_behavior_evidence_graph
from .semantic_ir import build_semantic_ir
from .reconstruction_verify import verify_reconstruction
from .gui_state import build_gui_state_machine
from .gui_xaml import extract_xaml_ui_evidence
from .memory import memory_address_map, memory_diff, memory_snapshot
from .engine import engine_analyze
from .android import android_analyze
from .ios import ios_analyze, ipa_analyze
from .protocol import protocol_analyze, protocol_capture, protocol_infer, protocol_summarize
from .pe_deep import pe_deep_scan
from .debugger_import import debugger_session_import
from ..source_reconstruction import attach_source_validation, reconstruct_source_project
from .yara_tools import yara_scan

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_RE = re.compile((rb"(?:[\x20-\x7e]\x00){4,}"))
SUSPICIOUS_SECTION_NAMES = {"upx0", "upx1", "aspack", ".aspack", ".adata", ".packed", "petite"}
PACKER_IMPORT_HINTS = {
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
}
ANTI_ANALYSIS_INDICATORS = {
    "debugger": ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstring"),
    "timing": ("queryperformancecounter", "gettickcount", "rdtsc"),
    "virtualization": ("vbox", "virtualbox", "vmware", "qemu", "sandboxie", "wine_get_version"),
    "process_or_window_probe": ("findwindow", "createtoolhelp32snapshot", "process32first", "process32next"),
    "exception_or_guard": ("setunhandledexceptionfilter", "vectoredexceptionhandler", "guard_page"),
}


def reconstruct_project(
    path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    analysis: Dict[str, Any] | None = None,
    *,
    strategy: str = "auto",
    validate: bool = False,
    validation_options: Dict[str, Any] | None = None,
    runtime_validation_spec: Dict[str, Any] | str | os.PathLike[str] | None = None,
    behavior_validation_spec: Dict[str, Any] | str | os.PathLike[str] | None = None,
    behavior_original_dir: str | os.PathLike[str] | None = None,
) -> Dict[str, Any]:
    """Adapt the legacy tool call shape to the multi-stack source API."""

    result = reconstruct_source_project(
        path,
        out_dir,
        analysis,
        strategy=strategy,
        validate=False,
        runtime_validation_spec=runtime_validation_spec,
        behavior_validation_spec=behavior_validation_spec,
        behavior_original_dir=behavior_original_dir,
    )
    _attach_reconstruction_compatibility(result)
    if validate:
        attach_source_validation(result, validation_options=validation_options)
    return result


def _attach_reconstruction_compatibility(result: Dict[str, Any]) -> None:
    """Preserve the legacy report/session contract around multi-stack output."""

    project_dir_value = result.get("project_dir")
    project = result.get("project")
    if not isinstance(project_dir_value, (str, os.PathLike)) or not isinstance(project, dict):
        return
    project_dir = Path(project_dir_value)
    if not project_dir.is_dir():
        return

    relative_sources = sorted(
        {
            str(item.get("path") or "").replace("\\", "/")
            for item in project.get("files") or []
            if isinstance(item, dict)
            and Path(str(item.get("path") or "")).suffix.lower()
            in {".c", ".cc", ".cpp", ".cxx", ".cs", ".java", ".js", ".kt", ".kts", ".mjs", ".py"}
        }
        - {""}
    )

    if result.get("output_stack") == "cmake-c":
        implementation = project_dir / "src" / "reconstructed.c"
        compatibility_source = project_dir / "src" / "functions.c"
        if implementation.is_file():
            compatibility_source.write_text(implementation.read_text(encoding="utf-8"), encoding="utf-8")
            relative_sources.append("src/functions.c")
            _declare_reconstruction_artifact(result, project_dir, "src/functions.c", "source")

    relative_sources = sorted(set(relative_sources))
    tasks = []
    for index, relative_path in enumerate(relative_sources, start=1):
        module = Path(relative_path).stem
        task_slug = re.sub(r"[^A-Za-z0-9_]+", "_", module).strip("_").lower() or f"module_{index}"
        tasks.append(
            {
                "name": f"reconstruct_{task_slug}_{index:02d}",
                "description": f"Review and refine generated source `{relative_path}`.",
                "status": "pending",
                "metadata": {"module": module, "module_file": relative_path},
                "result": None,
                "error": None,
                "subtasks": [],
            }
        )

    plan = {"status": "planned", "tasks": tasks}
    plan_relative = "analysis/reconstruction_plan.json"
    plan_path = project_dir / Path(plan_relative)
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text(json.dumps(plan, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _declare_reconstruction_artifact(result, project_dir, plan_relative, "analysis")

    result["reconstruction_plan"] = plan
    result["task_count"] = len(tasks)
    result["next_task"] = tasks[0]["name"] if tasks else None
    result["module_count"] = len({task["metadata"]["module"] for task in tasks})
    result["module_files"] = relative_sources


def _declare_reconstruction_artifact(
    result: Dict[str, Any],
    project_dir: Path,
    relative_path: str,
    kind: str,
) -> None:
    absolute_path = str(project_dir / Path(relative_path))
    artifacts = result.setdefault("artifacts", [])
    if isinstance(artifacts, list) and not any(
        isinstance(item, dict) and item.get("name") == relative_path for item in artifacts
    ):
        artifacts.append({"name": relative_path, "path": absolute_path, "kind": kind})
    generated_files = result.setdefault("generated_files", [])
    if isinstance(generated_files, list) and absolute_path not in generated_files:
        generated_files.append(absolute_path)


def register_builtin_tools(executor: ToolExecutor | None = None) -> ToolExecutor:
    """Register all built-in static-analysis tools on an executor."""

    executor = executor or ToolExecutor()
    executor.register("file_info", file_info)
    executor.register("hash", hash_file)
    executor.register("strings_extract", strings_extract)
    executor.register("pe_header_scan", pe_header_scan)
    executor.register("pe_deep_scan", pe_deep_scan)
    executor.register("section_entropy_scan", section_entropy_scan)
    executor.register("capstone_disassemble_stub", capstone_disassemble_stub)
    executor.register("packer_detect", packer_detect)
    executor.register("anti_detection_analyze", anti_detection_analyze)
    executor.register("debugger_session_import", debugger_session_import)
    executor.register("yara_scan", yara_scan)
    executor.register("yara_scan_stub", yara_scan_stub)
    executor.register("reconstruct_project", reconstruct_project)
    executor.register("memory_snapshot", memory_snapshot)
    executor.register("memory_diff", memory_diff)
    executor.register("memory_address_map", memory_address_map)
    executor.register("external_command", external_command)
    executor.register("frida_check", frida_check)
    executor.register("frida_trace", frida_trace)
    executor.register("frida_hook_profiles", frida_hook_profiles)
    executor.register("frida_install_guide", frida_install_guide)
    executor.register("binary_patch_apply", binary_patch_apply_plan)
    executor.register("binary_patch_rollback", binary_patch_rollback_plan)
    executor.register("validate_patch_plan", validate_patch_plan)
    executor.register("android_elf_patch_plan", android_elf_patch_plan)
    executor.register("android_elf_patch_verify", android_elf_patch_verify)
    executor.register("dll_proxy_generate", dll_proxy_generate)
    executor.register("procmon_check", procmon_check)
    executor.register("procmon_trace", procmon_trace)
    executor.register("procmon_install_guide", procmon_install_guide)
    executor.register("ghidra_check", ghidra_check)
    executor.register("ghidra_decompile", ghidra_decompile)
    executor.register("ghidra_install_guide", ghidra_install_guide)
    executor.register("gui_fingerprint", gui_fingerprint)
    executor.register("gui_resource_extract", gui_resource_extract)
    executor.register("gui_runtime_probe", gui_runtime_probe)
    executor.register("gui_strategy_select", gui_strategy_select)
    executor.register("gui_visual_parse", gui_visual_parse)
    executor.register("gui_visual_regression", gui_visual_regression)
    executor.register("gui_world_projection", gui_world_projection)
    executor.register("gui_evidence_graph", build_gui_evidence_graph)
    executor.register("gui_behavior_graph", build_behavior_evidence_graph)
    executor.register("semantic_ir_build", build_semantic_ir)
    executor.register("reconstruction_verify", verify_reconstruction)
    executor.register("gui_state_machine", build_gui_state_machine)
    executor.register("gui_xaml_extract", extract_xaml_ui_evidence)
    executor.register("reconstruct_gui_project", reconstruct_gui_project)
    executor.register("engine_analyze", engine_analyze)
    executor.register("android_analyze", android_analyze)
    executor.register("ios_analyze", ios_analyze)
    executor.register("ipa_analyze", ipa_analyze)
    executor.register("protocol_capture", protocol_capture)
    executor.register("protocol_infer", protocol_infer)
    executor.register("protocol_summarize", protocol_summarize)
    executor.register("protocol_analyze", protocol_analyze)
    return executor


def file_info(path: str | os.PathLike[str]) -> Dict[str, Any]:
    p = _require_file(path)
    st = p.stat()
    return {
        "path": str(p),
        "name": p.name,
        "size": st.st_size,
        "suffix": p.suffix,
        "is_file": p.is_file(),
    }


def hash_file(path: str | os.PathLike[str], algorithms: Iterable[str] = ("md5", "sha1", "sha256")) -> Dict[str, Any]:
    p = _require_file(path)
    hashers = {name: hashlib.new(name) for name in algorithms}
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            for h in hashers.values():
                h.update(chunk)
    return {"path": str(p), "hashes": {name: h.hexdigest() for name, h in hashers.items()}}


def strings_extract(path: str | os.PathLike[str], min_length: int = 4, limit: int = 1000) -> Dict[str, Any]:
    p = _require_file(path)
    data = p.read_bytes()
    ascii_strings = [m.group(0).decode("ascii", errors="replace") for m in PRINTABLE_RE.finditer(data)]
    utf16_strings = [m.group(0).decode("utf-16le", errors="ignore") for m in UTF16LE_RE.finditer(data)]
    strings = [s for s in ascii_strings + utf16_strings if len(s) >= min_length]
    return {"path": str(p), "count": len(strings), "strings": strings[:limit], "truncated": len(strings) > limit}


def pe_header_scan(path: str | os.PathLike[str]) -> ToolResult | Dict[str, Any]:
    p = _require_file(path)
    try:
        import pefile  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        return _unavailable("pe_header_scan", "pefile", exc)

    pe = pefile.PE(str(p), fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        pass
    sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        sections.append(
            {
                "name": name,
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "entropy": float(section.get_entropy()),
            }
        )
    imports = _extract_pe_imports(pe)
    return {
        "path": str(p),
        "machine": int(pe.FILE_HEADER.Machine),
        "number_of_sections": int(pe.FILE_HEADER.NumberOfSections),
        "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
        "entry_point": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
        "sections": sections,
        "imports": imports,
    }


def section_entropy_scan(path: str | os.PathLike[str]) -> Dict[str, Any]:
    p = _require_file(path)
    data = p.read_bytes()
    sections = _fallback_sections(data)
    pe_sections = _try_pe_sections(p)
    if pe_sections:
        sections = pe_sections
    return {"path": str(p), "sections": sections, "max_entropy": max((s["entropy"] for s in sections), default=0.0)}


def capstone_disassemble_stub(
    path: str | os.PathLike[str],
    offset: int = 0,
    size: int = 64,
    arch: str = "x86",
    mode: str = "32",
) -> ToolResult | Dict[str, Any]:
    p = _require_file(path)
    try:
        import capstone  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            tool="capstone_disassemble_stub",
            status="unavailable",
            error=f"optional dependency capstone unavailable: {exc}",
            data={"path": str(p), "stub": True, "instructions": []},
        )

    arch_const = capstone.CS_ARCH_X86 if arch == "x86" else capstone.CS_ARCH_X86
    mode_const = capstone.CS_MODE_64 if str(mode) == "64" else capstone.CS_MODE_32
    md = capstone.Cs(arch_const, mode_const)
    blob = p.read_bytes()[offset : offset + size]
    instructions = [
        {"address": int(i.address + offset), "mnemonic": i.mnemonic, "op_str": i.op_str, "bytes": i.bytes.hex()}
        for i in md.disasm(blob, 0)
    ]
    return {"path": str(p), "offset": offset, "size": size, "instructions": instructions, "stub": False}


def packer_detect(path: str | os.PathLike[str]) -> Dict[str, Any]:
    p = _require_file(path)
    entropy = section_entropy_scan(p)["sections"]
    strings = strings_extract(p, limit=5000)["strings"]
    lower_strings = {s.lower() for s in strings}
    indicators: List[Dict[str, Any]] = []

    for section in entropy:
        name = str(section.get("name", "")).lower()
        value = float(section.get("entropy", 0.0))
        if name in SUSPICIOUS_SECTION_NAMES or name.startswith("upx"):
            indicators.append({"type": "section_name", "section": name, "reason": "known packer-like section name"})
        if value >= 7.2:
            indicators.append({"type": "high_entropy", "section": name, "entropy": round(value, 4)})

    for hint in PACKER_IMPORT_HINTS:
        if hint.lower() in lower_strings:
            indicators.append({"type": "import_or_string", "value": hint})

    score = min(100, len(indicators) * 25)
    return {
        "path": str(p),
        "packed_likely": score >= 50,
        "score": score,
        "indicators": indicators,
    }


def anti_detection_analyze(path: str | os.PathLike[str]) -> Dict[str, Any]:
    """Identify anti-analysis behavior without generating bypass or concealment steps."""

    p = _require_file(path)
    raw_strings = strings_extract(p, limit=20000)["strings"]
    normalized = {str(value).lower() for value in raw_strings}
    findings: list[Dict[str, Any]] = []
    category_counts: Counter[str] = Counter()
    for category, indicators in ANTI_ANALYSIS_INDICATORS.items():
        for indicator in indicators:
            matches = sorted(value for value in normalized if indicator in value)[:10]
            if not matches:
                continue
            category_counts[category] += 1
            findings.append(
                {
                    "category": category,
                    "indicator": indicator,
                    "evidence": matches,
                    "interpretation": "The sample may inspect or disrupt analysis conditions; validate dynamically in an isolated lab.",
                }
            )
    score = min(100, sum(category_counts.values()) * 15 + len(category_counts) * 10)
    return {
        "status": "ok",
        "path": str(p),
        "analysis_scope": "defensive_detection_only",
        "risk_score": score,
        "anti_analysis_likely": score >= 35,
        "category_counts": dict(sorted(category_counts.items())),
        "findings": findings,
        "safety_boundary": "No evasion, hiding, bypass, unhooking, or security-control suppression instructions are produced.",
    }


def yara_scan_stub(path: str | os.PathLike[str], rules_path: str | os.PathLike[str] | None = None) -> ToolResult | Dict[str, Any]:
    """Backward-compatible alias for the real YARA scanner."""

    return yara_scan(path=path, rules_path=rules_path)


def external_command(
    command: List[str],
    allow_external: bool = False,
    timeout: float = 10.0,
    cwd: str | os.PathLike[str] | None = None,
) -> ToolResult | Dict[str, Any]:
    if not allow_external:
        return ToolResult(
            tool="external_command",
            status="unavailable",
            error="external commands are disabled by default; pass allow_external=True",
            data={"command": command},
        )
    if not command or not isinstance(command, list):
        raise ValueError("command must be a non-empty list")
    executable = shutil.which(command[0])
    if executable is None:
        raise FileNotFoundError(command[0])
    completed = subprocess.run(
        [executable, *command[1:]],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
        check=False,
    )
    return {
        "command": [executable, *command[1:]],
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _require_file(path: str | os.PathLike[str]) -> Path:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(str(p))
    return p


def _unavailable(tool: str, dependency: str, exc: BaseException, data: Dict[str, Any] | None = None) -> ToolResult:
    return ToolResult(
        tool=tool,
        status="unavailable",
        error=f"optional dependency {dependency} unavailable: {exc}",
        data=data or {},
    )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _fallback_sections(data: bytes, chunk_size: int = 4096) -> List[Dict[str, Any]]:
    if not data:
        return [{"name": "whole_file", "offset": 0, "size": 0, "entropy": 0.0}]
    chunks = []
    for index, offset in enumerate(range(0, len(data), chunk_size)):
        chunk = data[offset : offset + chunk_size]
        chunks.append({"name": f"chunk_{index}", "offset": offset, "size": len(chunk), "entropy": _entropy(chunk)})
    return chunks


def _try_pe_sections(path: Path) -> List[Dict[str, Any]]:
    try:
        import pefile  # type: ignore[import-not-found]

        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return []
    sections = []
    for section in pe.sections:
        raw = section.get_data()
        sections.append(
            {
                "name": section.Name.rstrip(b"\x00").decode("utf-8", errors="replace"),
                "offset": int(section.PointerToRawData),
                "size": int(section.SizeOfRawData),
                "virtual_address": int(section.VirtualAddress),
                "entropy": _entropy(raw),
            }
        )
    return sections


def _extract_pe_imports(pe: Any) -> List[Dict[str, Any]]:
    imports = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", errors="replace") if isinstance(entry.dll, bytes) else str(entry.dll)
        funcs = []
        for imp in entry.imports:
            funcs.append(
                {
                    "name": imp.name.decode("utf-8", errors="replace") if imp.name else None,
                    "ordinal": int(imp.ordinal) if imp.ordinal is not None else None,
                    "address": int(imp.address),
                }
            )
        imports.append({"dll": dll, "functions": funcs})
    return imports
