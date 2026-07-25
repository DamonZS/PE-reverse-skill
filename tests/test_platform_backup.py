from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import tarfile
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "platform_backup.py"


def run_backup(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_backup_dry_run_redacts_database_secret_and_plans_manifest(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "artifact.bin").write_bytes(b"evidence")
    result = run_backup(
        "backup",
        "--workspace",
        str(workspace),
        "--output",
        str(tmp_path / "backup"),
        "--database-url",
        "postgres://operator:do-not-leak@database.example/reverse",
        "--dry-run",
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "planned"
    assert payload["artifact_manifest"] is True
    assert payload["coordinated_freeze"] is True
    assert "do-not-leak" not in result.stdout


def test_restore_requires_explicit_confirmation_and_rejects_root_workspace(tmp_path: Path) -> None:
    manifest = tmp_path / "backup" / "manifest.json"
    manifest.parent.mkdir()
    manifest.write_text('{"schema_version":1,"artifacts":[]}', encoding="utf-8")
    database = "postgres://operator:test@database.example/reverse"
    refused = run_backup(
        "restore", "--workspace", str(tmp_path / "restore"), "--input", str(manifest.parent), "--staging-database-url", database
    )
    assert refused.returncode != 0
    assert "RESTORE_PLATFORM_BACKUP" in refused.stderr
    root_refused = run_backup(
        "restore",
        "--workspace",
        str(Path(tmp_path.anchor)),
        "--input",
        str(manifest.parent),
        "--confirm",
        "RESTORE_PLATFORM_BACKUP",
        "--staging-database-url",
        database,
    )
    assert root_refused.returncode != 0


def test_corrupt_backup_is_rejected_before_staging_database_or_workspace_changes(tmp_path: Path) -> None:
    source = tmp_path / "backup"
    source.mkdir()
    database_dump = source / "database-schema.dump"
    database_dump.write_bytes(b"database-snapshot")
    archive = source / "workspace-artifacts.tar.gz"
    with tarfile.open(archive, "w:gz"):
        pass
    manifest = {
        "schema_version": 3,
        "database_schema_dump": database_dump.name,
        "database_schema_dump_sha256": hashlib.sha256(database_dump.read_bytes()).hexdigest(),
        "artifact_archive": archive.name,
        "artifact_archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "migration_versions": [1, 2, 3, 4, 5, 6, 7, 8],
        "tenant_data": [],
        "artifacts": [],
    }
    (source / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    archive.write_bytes(archive.read_bytes() + b"corrupt")
    workspace = tmp_path / "restored"
    workspace.mkdir()
    sentinel = workspace / "keep.txt"
    sentinel.write_text("unchanged", encoding="utf-8")
    result = run_backup(
        "restore",
        "--workspace",
        str(workspace),
        "--input",
        str(source),
        "--staging-database-url",
        "postgres://invalid:invalid@127.0.0.1:1/staging",
        "--confirm",
        "RESTORE_PLATFORM_BACKUP",
    )
    assert result.returncode != 0
    assert "hash" in result.stderr.lower()
    assert sentinel.read_text(encoding="utf-8") == "unchanged"


def test_tenant_restore_uses_one_psql_transaction() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'lines = ["BEGIN;", "SET LOCAL session_replication_role=replica;"]' in source
    assert 'INSERT INTO schema_migrations(version,name)' in source
    assert "staging database migration versions do not match backup manifest" in source
    assert '"COMMIT;"' in source
    assert 'subprocess.run(["psql", *args, "-v", "ON_ERROR_STOP=1", "-f", "-"]' in source
    assert 'psql(db_args, process_env, f"INSERT INTO schema_migrations' not in source
