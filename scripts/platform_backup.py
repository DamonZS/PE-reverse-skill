#!/usr/bin/env python3
"""Consistent PostgreSQL and workspace-artifact backup/restore utility."""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse


RESTORE_CONFIRMATION = "RESTORE_PLATFORM_BACKUP"
TENANT_TABLES = [
    ("workspaces", "id="),
    ("users", "workspace_id="),
    ("api_tokens", "user_id IN (SELECT id FROM users WHERE workspace_id="),
    ("experiments", "workspace_id="),
    ("flow_events", "experiment_id IN (SELECT id FROM experiments WHERE workspace_id="),
    ("knowledge_documents", "workspace_id="),
    ("provider_usage", "workspace_id="),
    ("provider_configs", "workspace_id="),
    ("worker_leases", "workspace_id="),
    ("audit_events", "workspace_id="),
    ("audit_outbox", "workspace_id="),
    ("oauth_states", "workspace_id="),
    ("oauth_exchange_codes", "workspace_id="),
]


def safe_managed_path(raw: str, label: str) -> Path:
    path = Path(raw).expanduser().resolve()
    anchor = Path(path.anchor).resolve()
    if path == anchor or len(path.parts) < 2:
        raise ValueError(f"{label} must not be a filesystem root")
    return path


def managed_child(root: Path, raw: str, label: str) -> Path:
    candidate = (root / raw).resolve()
    if candidate == root.resolve() or root.resolve() not in candidate.parents:
        raise ValueError(f"{label} must stay inside the backup directory")
    return candidate


def database_process(database_url: str) -> tuple[list[str], dict[str, str], str]:
    parsed = urlparse(database_url)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname or not parsed.path.strip("/"):
        raise ValueError("database URL must be a PostgreSQL URL")
    args = ["-h", parsed.hostname, "-p", str(parsed.port or 5432), "-U", unquote(parsed.username or ""), "-d", parsed.path.strip("/")]
    env = os.environ.copy()
    password_content = None
    if parsed.password:
        password_content = f"{parsed.hostname}:{parsed.port or 5432}:{parsed.path.strip('/')}:{unquote(parsed.username or '')}:{unquote(parsed.password)}\n"
    elif env.get("PGPASSFILE") and Path(env["PGPASSFILE"]).is_file():
        password_content = Path(env["PGPASSFILE"]).read_text(encoding="utf-8")
    if password_content is not None:
        password_file = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, prefix="reverse-analyzer-pgpass-")
        password_file.write(password_content)
        password_file.close()
        os.chmod(password_file.name, 0o600)
        env["PGPASSFILE"] = password_file.name
        env["REVERSE_ANALYZER_TEMP_PGPASSFILE"] = password_file.name
        atexit.register(Path(password_file.name).unlink, missing_ok=True)
    endpoint = f"{parsed.hostname}:{parsed.port or 5432}/{parsed.path.strip('/')}"
    return args, env, endpoint


def cleanup_database_environment(environment: dict[str, str]) -> None:
    path = environment.get("REVERSE_ANALYZER_TEMP_PGPASSFILE")
    if path:
        Path(path).unlink(missing_ok=True)


def tenant_where(table: str, prefix: str, workspace_id: str) -> str:
    literal = sql_literal(workspace_id)
    if table in {"api_tokens", "flow_events"}:
        return prefix + literal + ")"
    return prefix + literal


def copy_query(args: list[str], environment: dict[str, str], query: str, destination: Path) -> None:
    escaped = str(destination.resolve()).replace("'", "''")
    psql(args, environment, f"\\copy ({query}) TO {sql_literal(escaped)} WITH (FORMAT csv, HEADER true)")


def restore_csv(args: list[str], environment: dict[str, str], table: str, source: Path) -> None:
    escaped = str(source.resolve()).replace("'", "''")
    psql(args, environment, f"\\copy {table} FROM {sql_literal(escaped)} WITH (FORMAT csv, HEADER true)")


def restore_tenant_data(
    args: list[str],
    environment: dict[str, str],
    sources: list[tuple[str, Path]],
    migration_versions: list[int],
) -> None:
    lines = ["BEGIN;", "SET LOCAL session_replication_role=replica;"]
    for table, source in sources:
        escaped = str(source.resolve()).replace("'", "''")
        lines.append(f"\\copy {table} FROM {sql_literal(escaped)} WITH (FORMAT csv, HEADER true)")
    normalized_versions = [int(version) for version in migration_versions]
    for version in normalized_versions:
        lines.append(
            f"INSERT INTO schema_migrations(version,name) VALUES({version},{sql_literal('restored-backup-' + str(version))});"
        )
    expected_versions = ",".join(str(version) for version in normalized_versions)
    lines.append(
        "DO $$ DECLARE actual BIGINT[]; BEGIN "
        "SELECT array_agg(version ORDER BY version) INTO actual FROM schema_migrations; "
        f"IF actual IS DISTINCT FROM ARRAY[{expected_versions}]::BIGINT[] THEN "
        "RAISE EXCEPTION 'staging database migration versions do not match backup manifest'; "
        "END IF; END $$;"
    )
    lines.extend([
        "SELECT setval(pg_get_serial_sequence('flow_events','id'), COALESCE((SELECT max(id) FROM flow_events),1), EXISTS(SELECT 1 FROM flow_events));",
        "SELECT setval(pg_get_serial_sequence('audit_events','id'), COALESCE((SELECT max(id) FROM audit_events),1), EXISTS(SELECT 1 FROM audit_events));",
        "SELECT setval(pg_get_serial_sequence('audit_outbox','id'), COALESCE((SELECT max(id) FROM audit_outbox),1), EXISTS(SELECT 1 FROM audit_outbox));",
        "COMMIT;",
    ])
    subprocess.run(["psql", *args, "-v", "ON_ERROR_STOP=1", "-f", "-"], input="\n".join(lines) + "\n", env=environment, text=True, check=True)


class MaintenanceLease:
    def __init__(self, args: list[str], environment: dict[str, str], workspace_id: str, owner: str) -> None:
        self.args, self.environment, self.workspace_id, self.owner = args, environment, workspace_id, owner
        self.lost = threading.Event()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._heartbeat, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _heartbeat(self) -> None:
        while not self.stop.wait(10):
            try:
                query = (
                    "UPDATE platform_maintenance SET expires_at=now()+interval '1 minute' "
                    f"WHERE workspace_id={sql_literal(self.workspace_id)} AND owner={sql_literal(self.owner)} RETURNING owner"
                )
                if psql(self.args, self.environment, query) != self.owner:
                    self.lost.set()
                    return
            except BaseException:
                self.lost.set()
                return

    def assert_owned(self) -> None:
        if self.lost.is_set():
            raise RuntimeError("workspace maintenance lease was lost")

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=2)


def run_with_lease(command: list[str], environment: dict[str, str], lease: MaintenanceLease) -> None:
    process = subprocess.Popen(command, env=environment)
    while process.poll() is None:
        if lease.lost.wait(0.25):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            raise RuntimeError("workspace maintenance lease was lost")
    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, command)


def snapshot_workspace(workspace: Path, snapshot: Path, lease: MaintenanceLease) -> None:
    snapshot.mkdir()
    for source in sorted(workspace.rglob("*")):
        lease.assert_owned()
        relative = source.relative_to(workspace)
        if source.is_symlink():
            raise ValueError(f"workspace backup refuses symlink: {relative}")
        destination = snapshot / relative
        if source.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        elif source.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)


def file_manifest(workspace: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in sorted(workspace.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"workspace backup refuses symlink: {path.relative_to(workspace)}")
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        records.append({"path": path.relative_to(workspace).as_posix(), "size": path.stat().st_size, "sha256": digest.hexdigest()})
    return records


def validate_archive(archive: Path) -> None:
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            relative = PurePosixPath(member.name)
            if member.issym() or member.islnk() or relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"unsafe artifact archive member: {member.name}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def psql(args: list[str], environment: dict[str, str], query: str) -> str:
    command = ["psql", *args, "-v", "ON_ERROR_STOP=1", "-tAc", query]
    return subprocess.check_output(command, env=environment, text=True).strip()


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def acquire_maintenance_lock(args: list[str], environment: dict[str, str], workspace_id: str) -> str:
    owner = uuid.uuid4().hex
    query = (
        "WITH acquired AS ("
        f"INSERT INTO platform_maintenance(workspace_id,owner,expires_at) VALUES ({sql_literal(workspace_id)}, {sql_literal(owner)}, now() + interval '1 minute') "
        "ON CONFLICT(workspace_id) DO UPDATE SET owner=EXCLUDED.owner, expires_at=EXCLUDED.expires_at "
        "WHERE platform_maintenance.expires_at < now() RETURNING owner) SELECT owner FROM acquired"
    )
    if psql(args, environment, query) != owner:
        raise ValueError("workspace is already in maintenance")
    running = psql(args, environment, f"SELECT count(*) FROM experiments WHERE workspace_id={sql_literal(workspace_id)} AND status='running'")
    if int(running or "0"):
        release_maintenance_lock(args, environment, workspace_id, owner)
        raise ValueError("backup requires no running workers")
    return owner


def release_maintenance_lock(args: list[str], environment: dict[str, str], workspace_id: str, owner: str) -> None:
    subprocess.run(
        ["psql", *args, "-v", "ON_ERROR_STOP=1", "-c", f"DELETE FROM platform_maintenance WHERE workspace_id={sql_literal(workspace_id)} AND owner={sql_literal(owner)}"],
        env=environment,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def backup(args: argparse.Namespace) -> dict[str, object]:
    workspace = safe_managed_path(args.workspace, "workspace")
    output = safe_managed_path(args.output, "output")
    if not workspace.is_dir():
        raise ValueError("workspace does not exist")
    if output == workspace or workspace in output.parents:
        raise ValueError("backup output must stay outside the workspace")
    db_args, process_env, endpoint = database_process(args.database_url)
    if args.dry_run:
        cleanup_database_environment(process_env)
        return {"status": "planned", "database": endpoint, "workspace": str(workspace), "output": str(output), "artifact_manifest": True, "coordinated_freeze": True}
    partial = output.with_name(output.name + ".partial")
    if output.exists() or partial.exists():
        raise ValueError("backup output already exists")
    partial.mkdir(parents=True)
    owner = acquire_maintenance_lock(db_args, process_env, args.workspace_id)
    lease = MaintenanceLease(db_args, process_env, args.workspace_id, owner)
    lease.start()
    try:
        run_with_lease(["pg_dump", *db_args, "--schema-only", "--format=custom", "--file", str(partial / "database-schema.dump")], process_env, lease)
        lease.assert_owned()
        tenant_dir = partial / "tenant-data"
        tenant_dir.mkdir()
        tenant_data: list[dict[str, object]] = []
        for table, prefix in TENANT_TABLES:
            destination = tenant_dir / f"{table}.csv"
            where = tenant_where(table, prefix, args.workspace_id)
            copy_query(db_args, process_env, f"SELECT * FROM {table} WHERE {where}", destination)
            tenant_data.append({"table": table, "file": destination.relative_to(partial).as_posix(), "sha256": sha256_file(destination)})
            lease.assert_owned()
        snapshot = partial / "workspace-snapshot"
        snapshot_workspace(workspace, snapshot, lease)
        before = file_manifest(workspace)
        artifacts = file_manifest(snapshot)
        if before != artifacts or file_manifest(workspace) != before:
            raise ValueError("workspace changed while creating the frozen snapshot")
        with tarfile.open(partial / "workspace-artifacts.tar.gz", "w:gz") as bundle:
            for record in artifacts:
                lease.assert_owned()
                bundle.add(snapshot / str(record["path"]), arcname=str(record["path"]), recursive=False)
        verify_dir = partial / "workspace-verify"
        verify_dir.mkdir()
        validate_archive(partial / "workspace-artifacts.tar.gz")
        with tarfile.open(partial / "workspace-artifacts.tar.gz", "r:gz") as bundle:
            bundle.extractall(verify_dir, filter="data")
        if file_manifest(verify_dir) != artifacts:
            raise ValueError("published artifact archive failed independent manifest verification")
        shutil.rmtree(snapshot)
        shutil.rmtree(verify_dir)
        lease.assert_owned()
        manifest = {
            "schema_version": 3,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "database": endpoint,
            "database_schema_dump": "database-schema.dump",
            "database_schema_dump_sha256": sha256_file(partial / "database-schema.dump"),
            "tenant_data": tenant_data,
            "artifact_archive": "workspace-artifacts.tar.gz",
            "artifact_archive_sha256": sha256_file(partial / "workspace-artifacts.tar.gz"),
            "migration_versions": [int(value) for value in psql(db_args, process_env, "SELECT version FROM schema_migrations ORDER BY version").splitlines() if value],
            "workspace_id": args.workspace_id,
            "artifacts": artifacts,
        }
        (partial / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        partial.rename(output)
        return {"status": "completed", "output": str(output), "artifact_count": len(artifacts), "manifest": str(output / "manifest.json"), "coordinated_freeze": True}
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    finally:
        lease.close()
        release_maintenance_lock(db_args, process_env, args.workspace_id, owner)
        cleanup_database_environment(process_env)


def restore(args: argparse.Namespace) -> dict[str, object]:
    workspace = safe_managed_path(args.workspace, "workspace")
    source = safe_managed_path(args.input, "input")
    if not args.dry_run and args.confirm != RESTORE_CONFIRMATION:
        raise ValueError(f"restore requires --confirm {RESTORE_CONFIRMATION}")
    manifest_path = source / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("backup manifest does not exist")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 3 or not isinstance(manifest.get("artifacts"), list) or not isinstance(manifest.get("tenant_data"), list):
        raise ValueError("unsupported backup manifest")
    db_args, process_env, endpoint = database_process(args.staging_database_url)
    if args.dry_run:
        cleanup_database_environment(process_env)
        return {"status": "planned", "database": endpoint, "workspace": str(workspace), "input": str(source), "artifact_manifest": True, "staging_only": True}
    archive = managed_child(source, str(manifest.get("artifact_archive", "workspace-artifacts.tar.gz")), "artifact archive")
    dump = managed_child(source, str(manifest.get("database_schema_dump", "database-schema.dump")), "database schema dump")
    if not archive.is_file() or not dump.is_file():
        raise ValueError("backup database or artifact archive is missing")
    if sha256_file(dump) != manifest.get("database_schema_dump_sha256") or sha256_file(archive) != manifest.get("artifact_archive_sha256"):
        raise ValueError("backup hash validation failed")
    for record in manifest["tenant_data"]:
        data_file = managed_child(source, str(record.get("file", "")), "tenant database export")
        if not data_file.is_file() or sha256_file(data_file) != record.get("sha256"):
            raise ValueError("tenant database export hash validation failed")
    validate_archive(archive)
    if workspace.exists():
        raise ValueError("staging workspace must not already exist")
    staging_workspace = workspace.with_name(workspace.name + ".staging-" + uuid.uuid4().hex)
    staging_workspace.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as bundle:
        bundle.extractall(staging_workspace, filter="data")
    actual = {item["path"]: item for item in file_manifest(staging_workspace)}
    expected = {item["path"]: item for item in manifest["artifacts"]}
    if actual != expected:
        shutil.rmtree(staging_workspace, ignore_errors=True)
        raise ValueError("restored workspace does not match artifact consistency manifest")
    tables = psql(db_args, process_env, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
    if int(tables or "0"):
        shutil.rmtree(staging_workspace, ignore_errors=True)
        raise ValueError("staging database must be empty; refusing to modify an existing database")
    try:
        subprocess.run(["pg_restore", *db_args, "--no-owner", str(dump)], env=process_env, check=True)
        records_by_table = {str(record["table"]): record for record in manifest["tenant_data"]}
        restore_sources: list[tuple[str, Path]] = []
        for table, _prefix in TENANT_TABLES:
            record = records_by_table.get(table)
            if record is None:
                raise ValueError(f"tenant database export is missing table {table}")
            restore_sources.append((table, managed_child(source, str(record["file"]), "tenant database export")))
        restore_tenant_data(db_args, process_env, restore_sources, manifest.get("migration_versions", []))
        versions = [int(value) for value in psql(db_args, process_env, "SELECT version FROM schema_migrations ORDER BY version").splitlines() if value]
        if versions != manifest.get("migration_versions"):
            raise ValueError("staging database migration versions do not match backup manifest")
        staging_workspace.rename(workspace)
    except BaseException:
        shutil.rmtree(staging_workspace, ignore_errors=True)
        raise
    finally:
        cleanup_database_environment(process_env)
    return {"status": "staged", "workspace": str(workspace), "artifact_count": len(actual), "database": endpoint, "manual_cutover": "After independent verification, point the deployment at this staging database and workspace; no production database was modified."}


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Backup or restore the Reverse Analyzer platform")
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("backup", "restore"):
        command = commands.add_parser(name)
        command.add_argument("--workspace", required=True)
        command.add_argument("--dry-run", action="store_true")
        if name == "backup":
            command.add_argument("--database-url", default=os.environ.get("REVERSE_ANALYZER_DATABASE_URL", ""))
            command.add_argument("--workspace-id", default=None)
            command.add_argument("--output", required=True)
        else:
            command.add_argument("--staging-database-url", required=True)
            command.add_argument("--input", required=True)
            command.add_argument("--confirm", default="")
    return root


def main() -> int:
    args = parser().parse_args()
    if args.command == "backup" and not args.workspace_id:
        args.workspace_id = str(safe_managed_path(args.workspace, "workspace"))
    try:
        result = backup(args) if args.command == "backup" else restore(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
