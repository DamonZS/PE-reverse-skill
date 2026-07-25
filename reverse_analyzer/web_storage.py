"""Workspace-scoped persistence backends for the Web platform."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Callable, Mapping, Protocol


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class StorageBackend(Protocol):
    def put(self, workspace_id: str, collection: str, record_id: str, value: Mapping[str, Any]) -> None: ...
    def get(self, workspace_id: str, collection: str, record_id: str) -> dict[str, Any] | None: ...
    def list(self, workspace_id: str, collection: str) -> list[dict[str, Any]]: ...
    def delete(self, workspace_id: str, collection: str, record_id: str) -> bool: ...


@dataclass(frozen=True)
class StorageConfig:
    backend: str = "local"
    local_root: Path = Path(".reverse_analyzer/web-storage")
    database_url: str | None = None

    @classmethod
    def from_environment(cls, workspace: str | Path) -> "StorageConfig":
        root = Path(workspace).resolve()
        return cls(
            backend=os.environ.get("REVERSE_ANALYZER_STORAGE_BACKEND", "local").strip().lower(),
            local_root=Path(
                os.environ.get("REVERSE_ANALYZER_WEB_STORAGE_DIR", root / ".reverse_analyzer" / "web-storage")
            ).resolve(),
            database_url=os.environ.get("REVERSE_ANALYZER_DATABASE_URL") or None,
        )


class LocalJsonStorage:
    """Atomic JSON records, partitioned by validated workspace identifier."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, workspace_id: str, collection: str, record_id: str, value: Mapping[str, Any]) -> None:
        path = self._record_path(workspace_id, collection, record_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            handle.write(payload)
            temporary = Path(handle.name)
        temporary.replace(path)

    def get(self, workspace_id: str, collection: str, record_id: str) -> dict[str, Any] | None:
        path = self._record_path(workspace_id, collection, record_id)
        if not path.is_file():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"stored record is not an object: {path}")
        return value

    def list(self, workspace_id: str, collection: str) -> list[dict[str, Any]]:
        directory = self._collection_path(workspace_id, collection)
        if not directory.is_dir():
            return []
        records = []
        for path in sorted(directory.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                records.append(value)
        return records

    def delete(self, workspace_id: str, collection: str, record_id: str) -> bool:
        path = self._record_path(workspace_id, collection, record_id)
        if not path.is_file():
            return False
        path.unlink()
        return True

    def _collection_path(self, workspace_id: str, collection: str) -> Path:
        workspace = _safe_identifier(workspace_id, "workspace_id")
        group = _safe_identifier(collection, "collection")
        path = (self.root / workspace / group).resolve()
        path.relative_to(self.root)
        return path

    def _record_path(self, workspace_id: str, collection: str, record_id: str) -> Path:
        identifier = _safe_identifier(record_id, "record_id")
        return self._collection_path(workspace_id, collection) / f"{identifier}.json"


class PostgreSQLStorage:
    """PostgreSQL JSONB storage with workspace predicates on every operation."""

    def __init__(self, database_url: str, *, connect: Callable[..., Any] | None = None):
        if not database_url:
            raise ValueError("PostgreSQL storage requires REVERSE_ANALYZER_DATABASE_URL")
        self.database_url = database_url
        self._connect = connect or _load_psycopg_connect()

    def put(self, workspace_id: str, collection: str, record_id: str, value: Mapping[str, Any]) -> None:
        parameters = (_safe_identifier(workspace_id, "workspace_id"), _safe_identifier(collection, "collection"), _safe_identifier(record_id, "record_id"), json.dumps(dict(value)))
        with self._connect(self.database_url) as connection, connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO web_records (workspace_id, collection, record_id, payload) VALUES (%s, %s, %s, %s::jsonb) "
                "ON CONFLICT (workspace_id, collection, record_id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = CURRENT_TIMESTAMP",
                parameters,
            )

    def get(self, workspace_id: str, collection: str, record_id: str) -> dict[str, Any] | None:
        with self._connect(self.database_url) as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM web_records WHERE workspace_id = %s AND collection = %s AND record_id = %s",
                (_safe_identifier(workspace_id, "workspace_id"), _safe_identifier(collection, "collection"), _safe_identifier(record_id, "record_id")),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return dict(row[0]) if isinstance(row[0], Mapping) else json.loads(row[0])

    def list(self, workspace_id: str, collection: str) -> list[dict[str, Any]]:
        with self._connect(self.database_url) as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM web_records WHERE workspace_id = %s AND collection = %s ORDER BY created_at, record_id",
                (_safe_identifier(workspace_id, "workspace_id"), _safe_identifier(collection, "collection")),
            )
            rows = cursor.fetchall()
        return [dict(row[0]) if isinstance(row[0], Mapping) else json.loads(row[0]) for row in rows]

    def delete(self, workspace_id: str, collection: str, record_id: str) -> bool:
        with self._connect(self.database_url) as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM web_records WHERE workspace_id = %s AND collection = %s AND record_id = %s",
                (_safe_identifier(workspace_id, "workspace_id"), _safe_identifier(collection, "collection"), _safe_identifier(record_id, "record_id")),
            )
            return cursor.rowcount > 0


def create_storage_backend(config: StorageConfig) -> StorageBackend:
    if config.backend == "local":
        return LocalJsonStorage(config.local_root)
    if config.backend in {"postgres", "postgresql"}:
        return PostgreSQLStorage(config.database_url or "")
    raise ValueError(f"unsupported storage backend: {config.backend}")


def _safe_identifier(value: str, field: str) -> str:
    text = str(value).strip()
    if not _IDENTIFIER.fullmatch(text):
        raise ValueError(f"invalid {field}")
    return text


def _load_psycopg_connect() -> Callable[..., Any]:
    try:
        import psycopg  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("PostgreSQL storage requires the optional 'psycopg[binary]' package") from exc
    return psycopg.connect
