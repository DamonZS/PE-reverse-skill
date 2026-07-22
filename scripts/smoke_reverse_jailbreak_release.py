from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import venv
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator, Mapping


def _run(command: list[str], *, env: Mapping[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        check=True,
        env=dict(env) if env is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=180,
    )
    return completed.stdout


class _FixtureHandler(BaseHTTPRequestHandler):
    model = "fixture-model"
    chat_requests = 0
    request_lock = threading.Lock()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, body: bytes, *, content_type: str = "application/json") -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-RateLimit-Remaining-Requests", "100")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/v1/models":
            self.send_error(404)
            return
        if self.headers.get("Authorization") != "Bearer fixture-key":
            self.send_error(401)
            return
        self._send(json.dumps({"data": [{"id": self.model}]}).encode("utf-8"))

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        if self.headers.get("Authorization") != "Bearer fixture-key":
            self.send_error(401)
            return
        with self.request_lock:
            type(self).chat_requests += 1
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if payload.get("stream"):
            event = {
                "id": "fixture-stream",
                "object": "chat.completion.chunk",
                "model": self.model,
                "choices": [{"index": 0, "delta": {"content": "READY"}}],
            }
            body = f"data: {json.dumps(event)}\n\ndata: [DONE]\n\n".encode("utf-8")
            self._send(body, content_type="text/event-stream")
            return
        response = {
            "id": "fixture-response",
            "object": "chat.completion",
            "model": self.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "CONTROLLED_CANARY"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10},
        }
        self._send(json.dumps(response).encode("utf-8"))


@contextmanager
def _fixture_endpoint() -> Iterator[str]:
    _FixtureHandler.chat_requests = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://{host}:{port}/v1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


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
        strategies_payload = json.loads(
            _run([str(executable), "strategies", "--json"])
        )
        if not strategies_payload.get("strategies"):
            raise RuntimeError("installed CLI returned no strategies")
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

        campaign_path = Path(directory) / "campaign.json"
        run_output = Path(directory) / "run-output"
        benchmark_output = Path(directory) / "benchmark-output"
        campaign = json.loads(
            (release / "jailbreak-campaign.example.json").read_text(encoding="utf-8")
        )
        environment_variables = dict(os.environ)
        environment_variables["RJ_SMOKE_KEY"] = "fixture-key"
        with _fixture_endpoint() as base_url:
            campaign["max_rounds"] = 1
            campaign["target"].update(
                {
                    "base_url": base_url,
                    "model": _FixtureHandler.model,
                    "api_key_env": "RJ_SMOKE_KEY",
                    "max_retries": 0,
                    "requests_per_minute": 0,
                }
            )
            campaign_path.write_text(
                json.dumps(campaign, indent=2), encoding="utf-8"
            )
            doctor = json.loads(
                _run(
                    [
                        str(executable),
                        "doctor",
                        "--base-url",
                        base_url,
                        "--model",
                        _FixtureHandler.model,
                        "--api-key-env",
                        "RJ_SMOKE_KEY",
                        "--json",
                    ],
                    env=environment_variables,
                )
            )
            if doctor.get("status") != "ok":
                raise RuntimeError("installed doctor command did not pass")
            result = json.loads(
                _run(
                    [
                        str(executable),
                        "run",
                        str(campaign_path),
                        "--out",
                        str(run_output),
                        "--json",
                    ],
                    env=environment_variables,
                )
            )
            if not result.get("success"):
                raise RuntimeError("installed run command did not reach the fixture canary")
            requests_before_resume = _FixtureHandler.chat_requests
            resumed = json.loads(
                _run(
                    [
                        str(executable),
                        "resume",
                        str(campaign_path),
                        "--out",
                        str(run_output),
                        "--json",
                    ],
                    env=environment_variables,
                )
            )
            if resumed.get("attempt_count") != result.get("attempt_count"):
                raise RuntimeError("installed resume command changed completed attempts")
            if _FixtureHandler.chat_requests != requests_before_resume:
                raise RuntimeError("installed resume command issued an extra request")
            report = json.loads(
                _run([str(executable), "report", str(run_output), "--json"])
            )
            if not isinstance(report, dict):
                raise RuntimeError("installed report command returned invalid JSON")
            promotion = json.loads(
                _run(
                    [
                        str(executable),
                        "promote",
                        str(run_output),
                        "--secret-env",
                        "RJ_SMOKE_KEY",
                        "--json",
                    ],
                    env=environment_variables,
                )
            )
            if promotion.get("status") != "passed":
                raise RuntimeError("installed promote command rejected fixture evidence")
            benchmark = json.loads(
                _run(
                    [
                        str(executable),
                        "benchmark",
                        str(campaign_path),
                        "--out",
                        str(benchmark_output),
                        "--max-rounds",
                        "1",
                        "--algorithm",
                        "builtin,pair,tap,crescendo,evolution",
                        "--json",
                    ],
                    env=environment_variables,
                )
            )
            if len(benchmark.get("runs", [])) != 5:
                raise RuntimeError("installed benchmark command did not run all algorithms")
            if not all(
                item.get("completed_checkpoint_recovery")
                for item in benchmark.get("runs", [])
            ):
                raise RuntimeError("installed benchmark checkpoint recovery failed")

    print(
        json.dumps(
            {"status": "ok", "version": expected_version, "wheel": wheels[0].name},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
