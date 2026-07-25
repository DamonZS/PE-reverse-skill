"""Legacy Web helper functions retained for data migration tests.

The Python HTTP backend has been retired. Production and development Web
traffic is served exclusively by ``reverse-analyzer-server``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64
import binascii
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import secrets
from typing import Any, Mapping
from urllib.parse import parse_qs, unquote, urlparse

from .config import AnalyzerConfig, ensure_runtime_dirs, load_config
from .access_control import Identity, TokenRegistry
from .environment_validation import validate_external_environment
from .knowledge import KnowledgeBase
from .platform_catalog import build_platform_catalog
from .provider_runtime import ProviderRuntime
from .sandbox import detect_runtime
from .storage import storage_status
from .storage import create_experiment_store
from .web_events import WebEventLog
from .web_jobs import CONFIRMATION_PHRASE, WebJobManager


_MAX_BODY_BYTES = 64 * 1024
_MAX_UPLOAD_BYTES = 16 * 1024 * 1024
_MAX_RECORD_BYTES = 8 * 1024 * 1024
_EVIDENCE_NAMES = {
    "evidence-manifest.json",
    "evidence_manifest.json",
    "manifest.json",
}


def build_workspace_payload(config: AnalyzerConfig) -> dict[str, Any]:
    """Return a bounded, JSON-compatible snapshot for the Web console."""

    ensure_runtime_dirs(config)
    experiments = _load_experiments(config.workspace)
    capabilities = _load_capabilities(config.workspace)
    knowledge = _load_knowledge(config.knowledge_dir)
    evidence = _load_evidence(config.workspace)
    environment = build_environment_payload(execute_probes=False)
    status_counts: dict[str, int] = {}
    for item in experiments:
        status = str(item.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

    done = sum(item["status"] == "done" for item in capabilities)
    capability_total = len(capabilities)
    valid_evidence = sum(item.get("valid") is True for item in evidence)
    evidence_total = len(evidence)
    return {
        "generated_at": _utc_now(),
        "workspace": str(config.workspace),
        "mode": "connected",
        "summary": {
            "experiment_total": len(experiments),
            "active_total": sum(
                status_counts.get(status, 0) for status in ("queued", "planned", "running")
            ),
            "needs_attention": status_counts.get("failed", 0),
            "evidence_total": evidence_total,
            "evidence_valid": valid_evidence,
            "evidence_integrity": (
                round(valid_evidence / evidence_total * 100, 1) if evidence_total else None
            ),
            "capability_total": capability_total,
            "capability_done": done,
            "capability_readiness": (
                round(done / capability_total * 100, 1) if capability_total else 0.0
            ),
            "knowledge_total": len(knowledge),
            "toolchain_verified": environment["summary"].get("verified", 0),
            "toolchain_dependency_gated": environment["summary"].get("dependency_gated", 0),
            "acceptance_ready_to_run": environment["summary"].get(
                "acceptance_fixture_ready_to_run", 0
            ),
            "status_counts": status_counts,
        },
        "experiments": experiments,
        "capabilities": capabilities,
        "evidence": evidence,
        "knowledge": knowledge,
        "environment": environment,
    }


def build_environment_payload(*, execute_probes: bool = False) -> dict[str, Any]:
    """Return external toolchain and live-acceptance readiness without running targets."""

    report = validate_external_environment(execute_probes=execute_probes)
    summary = dict(report.get("summary") or {})
    workflows = [
        {
            "id": key,
            "status": value.get("status"),
            "verified": value.get("verified"),
            "missing": value.get("missing") or [],
            "note": value.get("note"),
        }
        for key, value in (report.get("workflows") or {}).items()
        if isinstance(value, Mapping)
    ]
    acceptance = [
        {
            "id": item.get("id"),
            "phase": item.get("phase"),
            "capability": item.get("capability"),
            "status": item.get("status"),
            "live_verified": item.get("live_verified"),
            "missing_gates": item.get("missing_gates") or [],
            "command": item.get("command"),
            "acceptance_boundary": item.get("acceptance_boundary"),
        }
        for item in report.get("acceptance_fixtures") or []
        if isinstance(item, Mapping)
    ]
    return {
        "generated_at": report.get("generated_at"),
        "host": report.get("host") or {},
        "execute_probes": bool(report.get("execute_probes")),
        "summary": summary,
        "workflows": workflows,
        "acceptance_fixtures": acceptance,
        "sandbox": detect_runtime(),
        "storage": storage_status(os.environ.get("REVERSE_ANALYZER_WORKSPACE", ".")),
        "providers": ProviderRuntime().profiles(),
    }


def create_experiment_plan(config: AnalyzerConfig, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Create a queued plan without executing the target."""

    raw_target = str(payload.get("target") or "").strip()
    if not raw_target:
        raise ValueError("target is required")
    requested = Path(raw_target)
    target = requested if requested.is_absolute() else config.workspace / requested
    resolved = target.resolve()
    try:
        resolved.relative_to(config.workspace.resolve())
    except ValueError as exc:
        raise ValueError("target must stay inside the configured workspace") from exc
    if not resolved.is_file():
        raise ValueError("target must be an existing file")

    mode = str(payload.get("mode") or "evidence-first").strip()
    options = _mode_options(mode)
    store = create_experiment_store(config.workspace)
    record = store.create(
        resolved,
        options=options,
        metadata={
            "source": "web-console",
            "label": str(payload.get("label") or resolved.name).strip(),
            "execution_boundary": "plan-only",
        },
    )
    return {
        "experiment": record,
        "analysis_command": store.build_analysis_command(record["id"]),
        "executed": False,
        "execution_boundary": "The Web API records a queued experiment and never executes the target.",
    }


def serve_web_console(
    *,
    workspace: str | Path | None = None,
    frontend_dir: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8090,
) -> ThreadingHTTPServer:
    del workspace, frontend_dir, host, port
    raise RuntimeError(
        "The Python Web backend has been retired; start reverse-analyzer-server "
        "or run 'python -m reverse_analyzer web' to delegate to the Go control plane."
    )


def _handler_factory(config: AnalyzerConfig, frontend_root: Path):
    event_log = WebEventLog(config.workspace)
    job_manager = WebJobManager(config.workspace, event_log=event_log)
    job_manager.recover_stale_running()
    auth_token = _web_auth_token()
    token_registry = TokenRegistry(config.workspace / ".reverse_analyzer" / "auth.json")

    class WebConsoleHandler(BaseHTTPRequestHandler):
        server_version = "ReverseAnalyzerWeb/0.1"

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/api/health":
                self._json(
                    {
                        "status": "ok",
                        "workspace": str(config.workspace),
                        "generated_at": _utc_now(),
                    }
                )
                return
            if parsed.path.startswith("/api/") and not self._authorized(auth_token):
                self._unauthorized(auth_token)
                return
            if parsed.path == "/api/workspace":
                self._json(build_workspace_payload(config))
                return
            if parsed.path == "/api/environment":
                query = parse_qs(parsed.query)
                self._json(
                    build_environment_payload(
                        execute_probes=(query.get("probe") or [""])[0] in {"1", "true", "yes"}
                    )
                )
                return
            if parsed.path == "/api/platform/catalog":
                self._json(build_platform_catalog(config.workspace))
                return
            if parsed.path == "/api/providers":
                self._json({"providers": ProviderRuntime().profiles(), "fallback": "rule_based"})
                return
            if parsed.path.startswith("/api/experiments/"):
                self._handle_experiment_get(parsed.path, parse_qs(parsed.query))
                return
            if parsed.path == "/api/artifacts":
                self._handle_artifact_get(parse_qs(parsed.query))
                return
            if parsed.path == "/api/knowledge":
                self._handle_knowledge_get(parse_qs(parsed.query))
                return
            self._serve_static(parsed.path)

        def do_HEAD(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path.startswith("/api/"):
                if parsed.path != "/api/health" and not self._authorized(auth_token):
                    self._unauthorized(auth_token, head_only=True)
                    return
                self.send_response(HTTPStatus.NO_CONTENT)
                self._security_headers()
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            self._serve_static(parsed.path, head_only=True)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path.startswith("/api/") and not self._authorized(auth_token):
                self._unauthorized(auth_token)
                return
            if parsed.path == "/api/uploads":
                self._handle_upload()
                return
            if parsed.path == "/api/experiments":
                try:
                    payload = self._read_json()
                    result = create_experiment_plan(config, payload)
                except (ValueError, json.JSONDecodeError) as exc:
                    self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                    return
                self._json(result, status=HTTPStatus.CREATED)
                return
            if parsed.path.startswith("/api/experiments/"):
                self._handle_experiment_post(parsed.path)
                return
            if parsed.path == "/api/knowledge":
                self._handle_knowledge_post()
                return
            if parsed.path == "/api/providers/test":
                try:
                    payload = self._read_json()
                    name = str(payload.get("name") or "rule_based")
                    self._json(ProviderRuntime().test(name))
                except (ValueError, json.JSONDecodeError) as exc:
                    self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

        def do_PATCH(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path.startswith("/api/") and not self._authorized(auth_token):
                self._unauthorized(auth_token)
                return
            if parsed.path.startswith("/api/knowledge/"):
                self._handle_knowledge_patch(parsed.path)
                return
            self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

        def do_DELETE(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path.startswith("/api/") and not self._authorized(auth_token):
                self._unauthorized(auth_token)
                return
            if parsed.path.startswith("/api/knowledge/"):
                self._handle_knowledge_delete(parsed.path)
                return
            self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _read_json(self, *, max_bytes: int = _MAX_BODY_BYTES) -> dict[str, Any]:
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ValueError("invalid Content-Length") from exc
            if length <= 0 or length > max_bytes:
                raise ValueError(f"request body must be between 1 byte and {max_bytes} bytes")
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            return payload

        def _handle_experiment_get(self, request_path: str, query: Mapping[str, list[str]]) -> None:
            parts = _api_parts(request_path)
            if len(parts) not in {2, 3}:
                self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            experiment_id = parts[1]
            try:
                if len(parts) == 3 and parts[2] == "events":
                    events = event_log.list_events(
                        experiment_id,
                        after=_optional_int((query.get("after") or [None])[0]),
                        limit=_optional_int((query.get("limit") or [None])[0]) or 200,
                    )
                    accept = self.headers.get("Accept", "")
                    if "text/event-stream" in accept:
                        self._bytes(
                            event_log.as_sse(events),
                            content_type="text/event-stream; charset=utf-8",
                            cache_control="no-store",
                        )
                    else:
                        self._json({"events": events})
                    return
                if len(parts) == 2:
                    self._json({"experiment": ExperimentStore(config.workspace).get(experiment_id)})
                    return
            except (OSError, ValueError) as exc:
                self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

        def _handle_experiment_post(self, request_path: str) -> None:
            parts = _api_parts(request_path)
            if len(parts) != 3:
                self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            experiment_id, action = parts[1], parts[2]
            try:
                payload = self._read_json() if action == "execute" else {}
                if action == "execute":
                    result = job_manager.execute(
                        experiment_id,
                        confirmation=payload.get("confirmation") or payload.get("confirm_execute"),
                    )
                    self._json(result, status=HTTPStatus.ACCEPTED)
                    return
                if action == "cancel":
                    self._json(job_manager.cancel(experiment_id), status=HTTPStatus.ACCEPTED)
                    return
                if action == "retry":
                    self._json(job_manager.retry(experiment_id), status=HTTPStatus.CREATED)
                    return
            except PermissionError as exc:
                self._json(
                    {"error": str(exc), "confirmation_required": CONFIRMATION_PHRASE},
                    status=HTTPStatus.FORBIDDEN,
                )
                return
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

        def _handle_upload(self) -> None:
            try:
                payload = self._read_json(max_bytes=_MAX_UPLOAD_BYTES + 4096)
                result = _save_upload(config, payload)
            except (ValueError, json.JSONDecodeError, binascii.Error) as exc:
                self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._json(result, status=HTTPStatus.CREATED)

        def _handle_artifact_get(self, query: Mapping[str, list[str]]) -> None:
            relative = (query.get("path") or [""])[0]
            try:
                result = _read_artifact(config, relative)
            except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._json(result)

        def _handle_knowledge_get(self, query: Mapping[str, list[str]]) -> None:
            q = (query.get("q") or [""])[0].strip()
            try:
                kb = KnowledgeBase(config.knowledge_dir)
                if q:
                    self._json({"matches": kb.search_documents(q, limit=25)})
                else:
                    self._json({"documents": kb.list_documents(limit=200)})
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

        def _handle_knowledge_post(self) -> None:
            try:
                payload = self._read_json()
                record = _upsert_knowledge(config, payload)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._json({"document": record}, status=HTTPStatus.CREATED)

        def _handle_knowledge_patch(self, request_path: str) -> None:
            parts = _api_parts(request_path)
            if len(parts) != 2:
                self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            try:
                payload = self._read_json()
                record = _upsert_knowledge(config, payload, document_id=parts[1])
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._json({"document": record})

        def _handle_knowledge_delete(self, request_path: str) -> None:
            parts = _api_parts(request_path)
            if len(parts) != 2:
                self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            try:
                deleted = _delete_knowledge(config, parts[1])
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._json({"deleted": deleted})

        def _serve_static(self, request_path: str, *, head_only: bool = False) -> None:
            relative = request_path.lstrip("/") or "index.html"
            candidate = (frontend_root / relative).resolve()
            try:
                candidate.relative_to(frontend_root)
            except ValueError:
                self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            if not candidate.is_file():
                candidate = frontend_root / "index.html"
            content = candidate.read_bytes()
            content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            self.send_response(HTTPStatus.OK)
            self._security_headers()
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            if not head_only:
                self.wfile.write(content)

        def _json(self, payload: Any, *, status: HTTPStatus = HTTPStatus.OK) -> None:
            content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._bytes(content, status=status, content_type="application/json; charset=utf-8", cache_control="no-store")

        def _bytes(
            self,
            content: bytes,
            *,
            status: HTTPStatus = HTTPStatus.OK,
            content_type: str,
            cache_control: str,
        ) -> None:
            self.send_response(status)
            self._security_headers()
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", cache_control)
            self.end_headers()
            self.wfile.write(content)

        def _authorized(self, token: str | None) -> bool:
            registry_enabled = token_registry.path.is_file()
            if not token and not registry_enabled:
                return True
            header = self.headers.get("Authorization", "")
            supplied = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else self.headers.get("X-API-Key", "").strip()
            identity: Identity | None = None
            if supplied and token and secrets.compare_digest(supplied, token):
                identity = Identity("legacy-web-token", "admin", "*", "environment")
            if identity is None:
                identity = token_registry.authenticate(supplied)
            return bool(identity and identity.allows(_request_permission(self.command, urlparse(self.path).path), str(config.workspace.resolve())))

        def _unauthorized(self, token: str | None, *, head_only: bool = False) -> None:
            payload = {
                "error": "authentication required",
                "auth": "Set Authorization: Bearer <token> or X-API-Key. Configure REVERSE_ANALYZER_WEB_TOKEN on the server.",
                "enabled": bool(token),
            }
            content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self._security_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(0 if head_only else len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("WWW-Authenticate", 'Bearer realm="reverse-analyzer"')
            self.end_headers()
            if not head_only:
                self.wfile.write(content)

        def _security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
                "style-src 'self' 'unsafe-inline'; script-src 'self'",
            )

    return WebConsoleHandler


def _load_experiments(workspace: Path) -> list[dict[str, Any]]:
    try:
        records = create_experiment_store(workspace).list(limit=100)
    except (OSError, ValueError):
        return []
    return [
        {
            "id": item.get("id"),
            "sample": item.get("sample"),
            "name": Path(str(item.get("sample") or "")).name,
            "status": item.get("status"),
            "created_at": item.get("created_at"),
            "updated_at": item.get("updated_at"),
            "options": item.get("options") or {},
            "summary": item.get("summary"),
            "artifacts": item.get("artifacts") or [],
            "metadata": item.get("metadata") or {},
        }
        for item in records
    ]


def _load_capabilities(workspace: Path) -> list[dict[str, Any]]:
    matrix = workspace / "docs" / "skill_parity_matrix.md"
    if not matrix.is_file():
        return []
    return _read_parity_rows(matrix)


def _read_parity_rows(matrix: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    statuses = {"done", "partial", "dependency-gated", "missing"}
    for line in matrix.read_text(encoding="utf-8-sig").splitlines():
        if not line.startswith("|"):
            continue
        columns = [column.strip() for column in line.strip("|").split("|")]
        if len(columns) < 9 or columns[1] not in statuses:
            continue
        rows.append(
            {
                "name": columns[0],
                "status": columns[1],
                "modules": columns[2],
                "detail": columns[3],
                "phase": columns[7],
                "acceptance_command": columns[8],
            }
        )
    return rows


def _load_knowledge(knowledge_dir: Path) -> list[dict[str, Any]]:
    try:
        return KnowledgeBase(knowledge_dir).list_documents(limit=100)
    except (OSError, ValueError, json.JSONDecodeError):
        return []


def _load_evidence(workspace: Path) -> list[dict[str, Any]]:
    candidates: list[Path] = []
    for directory in (
        workspace / "reports",
        workspace / "experiments",
        workspace / ".reverse_analyzer" / "artifacts",
    ):
        if not directory.is_dir():
            continue
        for path in directory.rglob("*.json"):
            if len(candidates) >= 200:
                break
            if path.name.lower() in _EVIDENCE_NAMES or "evidence" in path.name.lower():
                candidates.append(path)
    records: list[dict[str, Any]] = []
    for path in sorted(candidates, key=_modified_ns, reverse=True):
        try:
            if path.stat().st_size > _MAX_RECORD_BYTES:
                continue
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        valid = _evidence_valid(payload)
        records.append(
            {
                "path": _relative(path, workspace),
                "name": path.name,
                "kind": _evidence_kind(payload, path),
                "valid": valid,
                "entry_count": _evidence_entry_count(payload),
                "updated_at": datetime.fromtimestamp(
                    path.stat().st_mtime, tz=timezone.utc
                ).isoformat(),
            }
        )
    return records[:100]


def _mode_options(mode: str) -> dict[str, Any]:
    options = {
        "evidence-first": {},
        "pe-reconstruction": {"reconstruct": True},
        "protocol-review": {},
        "gui-evidence": {"gui": True, "gui_visual": True},
    }
    if mode not in options:
        raise ValueError("unsupported analysis mode")
    return options[mode]


def _web_auth_token() -> str | None:
    token = os.environ.get("REVERSE_ANALYZER_WEB_TOKEN", "").strip()
    return token or None


def _request_permission(method: str, path: str) -> str:
    if method in {"GET", "HEAD"}:
        return "artifact.read" if path == "/api/artifacts" else "workspace.read"
    if path.startswith("/api/knowledge"):
        return "knowledge.write"
    if path == "/api/providers/test":
        return "providers.manage"
    if path.endswith("/execute") or path.endswith("/cancel") or path.endswith("/retry"):
        return "analysis.execute"
    return "analysis.plan"


def _api_parts(request_path: str) -> list[str]:
    return [unquote(part) for part in request_path.strip("/").split("/") if part][1:]


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _save_upload(config: AnalyzerConfig, payload: Mapping[str, Any]) -> dict[str, Any]:
    filename = _safe_filename(str(payload.get("filename") or "sample.bin"))
    raw_content = str(payload.get("content_base64") or "").strip()
    if "," in raw_content and raw_content.split(",", 1)[0].lower().startswith("data:"):
        raw_content = raw_content.split(",", 1)[1]
    content = base64.b64decode(raw_content, validate=True)
    if not content or len(content) > _MAX_UPLOAD_BYTES:
        raise ValueError("upload content must be between 1 byte and 16 MiB")
    digest = hashlib.sha256(content).hexdigest()
    uploads = config.workspace / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    target = (uploads / f"{digest[:12]}-{filename}").resolve()
    target.relative_to(config.workspace.resolve())
    if not target.exists():
        target.write_bytes(content)
    return {
        "path": _relative(target, config.workspace),
        "filename": target.name,
        "size": len(content),
        "sha256": digest,
    }


def _safe_filename(value: str) -> str:
    cleaned = "".join(character if character.isalnum() or character in "._-" else "_" for character in value)
    cleaned = cleaned.strip("._") or "sample.bin"
    return cleaned[:120]


def _read_artifact(config: AnalyzerConfig, relative: str) -> dict[str, Any]:
    if not relative:
        raise ValueError("path is required")
    target = (config.workspace / relative).resolve()
    target.relative_to(config.workspace.resolve())
    if not target.is_file():
        raise ValueError("artifact file does not exist")
    if target.stat().st_size > _MAX_RECORD_BYTES:
        raise ValueError("artifact is too large to read through the Web API")
    content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    if target.suffix.lower() == ".json":
        return {
            "path": _relative(target, config.workspace),
            "content_type": "application/json",
            "json": json.loads(target.read_text(encoding="utf-8")),
        }
    return {
        "path": _relative(target, config.workspace),
        "content_type": content_type,
        "text": target.read_text(encoding="utf-8"),
    }


def _upsert_knowledge(
    config: AnalyzerConfig,
    payload: Mapping[str, Any],
    *,
    document_id: str | None = None,
) -> dict[str, Any]:
    return KnowledgeBase(config.knowledge_dir).add_document(
        str(payload.get("content") or ""),
        document_type=str(payload.get("type") or payload.get("document_type") or "memory"),
        title=str(payload.get("title") or ""),
        scope=str(payload.get("scope") or "global"),
        tags=payload.get("tags") if isinstance(payload.get("tags"), list) else [],
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
        document_id=document_id,
    )


def _delete_knowledge(config: AnalyzerConfig, document_id: str) -> bool:
    kb = KnowledgeBase(config.knowledge_dir)
    data = kb.load_documents()
    documents = data.setdefault("documents", {})
    if document_id not in documents:
        return False
    documents.pop(document_id, None)
    data["last_updated"] = _utc_now()
    kb.save_documents(data)
    return True


def _evidence_valid(payload: Any) -> bool | None:
    if not isinstance(payload, Mapping):
        return None
    if isinstance(payload.get("valid"), bool):
        return bool(payload["valid"])
    status = str(payload.get("status") or "").lower()
    if status in {"valid", "verified", "complete", "ok"}:
        return True
    if status in {"invalid", "failed"}:
        return False
    return None


def _evidence_entry_count(payload: Any) -> int:
    if not isinstance(payload, Mapping):
        return 0
    for key in ("entries", "files", "artifacts", "manifest_entries"):
        value = payload.get(key)
        if isinstance(value, list):
            return len(value)
    return 0


def _evidence_kind(payload: Any, path: Path) -> str:
    if isinstance(payload, Mapping):
        for key in ("kind", "type", "schema"):
            if payload.get(key):
                return str(payload[key])
    return path.stem


def _relative(path: Path, workspace: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return path.name


def _modified_ns(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return 0


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


__all__ = [
    "build_environment_payload",
    "build_workspace_payload",
    "create_experiment_plan",
    "serve_web_console",
]
