"""Runtime storage selection with JSON and optional PostgreSQL backends."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from .core.models import utc_now
from .runtime.experiments import ExperimentStore, SCHEMA_VERSION, _json_value


class PostgreSQLExperimentStore(ExperimentStore):
    """ExperimentStore-compatible PostgreSQL implementation.

    psycopg is imported only when this backend is selected, keeping local mode
    dependency-free.
    """

    def __init__(self, workspace: str | Path, database_url: str):
        super().__init__(workspace)
        try:
            import psycopg  # type: ignore
        except ImportError as exc:
            raise RuntimeError("PostgreSQL storage requires psycopg; install the postgres optional dependency") from exc
        self.database_url = database_url
        self._psycopg = psycopg

    def _connect(self):
        return self._psycopg.connect(self.database_url)

    def create(self, sample: str | Path, *, options: Mapping[str, Any] | None = None, metadata: Mapping[str, Any] | None = None) -> dict[str, Any]:
        now = utc_now()
        record = {"schema": SCHEMA_VERSION, "schema_version": SCHEMA_VERSION, "id": uuid4().hex, "sample": str(sample), "status": "queued", "created_at": now, "updated_at": now, "options": _json_value(dict(options or {})), "metadata": _json_value(dict(metadata or {})), "history": [{"timestamp": now, "status": "queued", "detail": "created"}], "artifacts": [], "summary": None}
        self._save(record)
        return record

    def get(self, experiment_id: str) -> dict[str, Any]:
        self._validate_experiment_id(experiment_id)
        with self._connect() as conn, conn.cursor() as cursor:
            cursor.execute("SELECT payload FROM experiments WHERE id=%s", (experiment_id,))
            row = cursor.fetchone()
        if row is None:
            raise KeyError(experiment_id)
        payload = row[0] if isinstance(row[0], Mapping) else json.loads(row[0])
        return self._validate_record(payload, expected_id=experiment_id)

    def list(self, limit: int | None = None) -> list[dict[str, Any]]:
        if limit is not None and limit < 0:
            raise ValueError("limit must be non-negative")
        query = "SELECT payload FROM experiments ORDER BY updated_at DESC"
        params: tuple[Any, ...] = ()
        if limit is not None:
            query += " LIMIT %s"
            params = (limit,)
        with self._connect() as conn, conn.cursor() as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()
        return [self._validate_record(row[0] if isinstance(row[0], Mapping) else json.loads(row[0])) for row in rows]

    def _save(self, experiment: Mapping[str, Any]) -> None:
        normalized = self._validate_record(_json_value(dict(experiment)))
        with self._connect() as conn, conn.cursor() as cursor:
            cursor.execute("""INSERT INTO experiments(id, workspace_id, status, created_at, updated_at, payload)
                VALUES (%s,%s,%s,%s,%s,%s::jsonb)
                ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at, payload=excluded.payload""",
                (normalized["id"], str(self.workspace.resolve()), normalized["status"], normalized["created_at"], normalized["updated_at"], json.dumps(normalized, ensure_ascii=False)))
            conn.commit()


def create_experiment_store(workspace: str | Path) -> ExperimentStore:
    url = os.getenv("REVERSE_ANALYZER_DATABASE_URL", "").strip()
    return PostgreSQLExperimentStore(workspace, url) if url else ExperimentStore(workspace)


def storage_status(workspace: str | Path) -> dict[str, Any]:
    url = os.getenv("REVERSE_ANALYZER_DATABASE_URL", "").strip()
    if not url:
        return {"backend": "json", "configured": True, "url_present": False, "migration": None, "reason": "set REVERSE_ANALYZER_DATABASE_URL to enable PostgreSQL"}
    try:
        import psycopg  # type: ignore  # noqa: F401
        driver = True
    except ImportError:
        driver = False
    return {"backend": "postgresql", "configured": driver, "url_present": True, "driver_ready": driver, "migration": "deploy/migrations/001_initial.sql"}


__all__ = ["PostgreSQLExperimentStore", "create_experiment_store", "storage_status"]
