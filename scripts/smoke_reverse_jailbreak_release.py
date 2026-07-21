from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


def _run(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=180,
    )
    return completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Install and smoke a reverse-jailbreak portable release"
    )
    parser.add_argument("release", type=Path)
    args = parser.parse_args()
    release = args.release.expanduser().resolve()
    wheels = sorted(release.glob("*.whl"))
    if len(wheels) != 1:
        parser.error("release directory must contain exactly one wheel")

    manifest = json.loads(
        (release / "release-manifest.json").read_text(encoding="utf-8")
    )
    expected_version = str(manifest.get("product_version") or "")
    if not expected_version:
        raise RuntimeError("release manifest has no product_version")

    with tempfile.TemporaryDirectory(prefix="reverse-jailbreak-smoke-") as directory:
        environment = Path(directory) / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(environment)
        python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        executable = environment / (
            "Scripts/reverse-jailbreak.exe"
            if sys.platform == "win32"
            else "bin/reverse-jailbreak"
        )
        _run([str(python), "-m", "pip", "install", str(wheels[0])])
        installed_version = _run(
            [
                str(python),
                "-c",
                "import importlib.metadata; print(importlib.metadata.version('reverse-analyzer'))",
            ]
        ).strip()
        if installed_version != expected_version:
            raise RuntimeError(
                f"installed version {installed_version!r} does not match "
                f"manifest version {expected_version!r}"
            )
        cli_version = _run([str(executable), "--version"]).strip()
        if cli_version != f"python -m reverse_analyzer.llm_jailbreak {expected_version}":
            raise RuntimeError(f"unexpected CLI version output: {cli_version!r}")
        profiles_payload = json.loads(
            _run([str(executable), "profiles", "--json"])
        )
        profiles = profiles_payload.get("profiles", [])
        if len(profiles) != 5:
            raise RuntimeError(f"expected five packaged profiles, got {len(profiles)}")
        _run(
            [
                str(executable),
                "validate",
                str(release / "jailbreak-campaign.example.json"),
                "--json",
            ]
        )
        verification = json.loads(
            _run([str(executable), "release-verify", str(release), "--json"])
        )
        if not verification.get("ok"):
            raise RuntimeError("installed CLI rejected the release manifest")

    print(
        json.dumps(
            {"status": "ok", "version": expected_version, "wheel": wheels[0].name},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
