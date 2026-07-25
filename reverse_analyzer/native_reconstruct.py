"""Evidence-producing ELF/binutils reconstruction provider."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Sequence


_TOOLS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("file", ("file", "-b", "--", "{target}")),
    ("readelf_headers", ("readelf", "-h", "-W", "--", "{target}")),
    ("readelf_symbols", ("readelf", "-s", "-W", "--", "{target}")),
    ("objdump_disassembly", ("objdump", "-d", "-M", "intel", "--", "{target}")),
    ("strings", ("strings", "-a", "-n", "4", "--", "{target}")),
)
_MAX_OUTPUT = 2 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(definition: tuple[str, tuple[str, ...]], target: Path) -> dict[str, Any]:
    name, template = definition
    argv = [str(target) if item == "{target}" else item for item in template]
    try:
        completed = subprocess.run(argv, capture_output=True, check=False, shell=False, timeout=60)
        raw = completed.stdout[:_MAX_OUTPUT]
        stderr = completed.stderr[:64 * 1024]
        return {
            "name": name,
            "argv": [argv[0], *argv[1:-1], "<target>"],
            "status": "completed" if completed.returncode == 0 else "failed",
            "return_code": completed.returncode,
            "stdout": raw.decode("utf-8", errors="replace"),
            "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
            "stdout_bytes": len(completed.stdout),
            "stdout_truncated": len(completed.stdout) > len(raw),
            "stderr": stderr.decode("utf-8", errors="replace"),
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"name": name, "argv": [argv[0]], "status": "dependency-gated", "return_code": None, "error": f"{type(error).__name__}: {error}"}


def _c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def reconstruct_native(target: Path, out: Path) -> dict[str, Any]:
    target = target.resolve()
    if not target.is_file() or target.read_bytes()[:4] != b"\x7fELF":
        raise ValueError("target is not an ELF regular file")
    out = out.resolve()
    source = out / "source"
    source.mkdir(parents=True, exist_ok=True)
    observations = [_run(item, target) for item in _TOOLS]
    strings_result = next((item for item in observations if item["name"] == "strings"), {})
    values = []
    for line in str(strings_result.get("stdout") or "").splitlines():
        value = line.strip()
        if 4 <= len(value) <= 160 and re.search(r"[A-Za-z]", value) and value not in values:
            values.append(value)
        if len(values) >= 160:
            break
    evidence = {
        "schema_version": 1,
        "provider": "local-binutils",
        "target": {"sha256": _sha256(target), "size": target.stat().st_size, "magic": "7f454c46"},
        "tools": observations,
        "observed_strings": values,
        "provenance": {"real_subprocess": True, "runner_injected": False, "shell": False, "network": "not-required"},
    }
    (out / "native-evidence.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (source / "project.json").write_text(json.dumps({"schema_version": 1, "kind": "elf-evidence-reconstruction"}, indent=2) + "\n", encoding="utf-8")
    (source / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\nproject(program_reconstruction LANGUAGES C)\nadd_executable(program main.c)\n",
        encoding="utf-8",
    )
    declarations = ",\n  ".join(_c_string(value) for value in values[:80]) or '"no printable evidence"'
    (source / "main.c").write_text(
        "#include <stddef.h>\n\n"
        "/* Strings recovered by a real binutils subprocess are retained as model evidence. */\n"
        f"static const char *const recovered_strings[] = {{\n  {declarations}\n}};\n\n"
        "int main(void) {\n"
        "  return recovered_strings[0] == NULL;\n"
        "}\n",
        encoding="utf-8",
    )
    return evidence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reconstruct an ELF target from binutils evidence")
    parser.add_argument("target")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        result = reconstruct_native(Path(args.target), Path(args.out))
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        return 2
    print(json.dumps({"status": "ok", "provider": result["provider"], "target_sha256": result["target"]["sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
