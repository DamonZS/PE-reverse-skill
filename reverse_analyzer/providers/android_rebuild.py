from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import zipfile
import zlib
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, Optional, Protocol

from reverse_analyzer.core.capabilities.models import (
    CapabilityArtifact,
    CapabilityArtifactBundle,
    CapabilityExecutionResult,
    CapabilityPlan,
    CapabilityRequest,
    CapabilityRollbackResult,
    CapabilityValidation,
)
from reverse_analyzer.providers.mock import MockCapabilityProvider


_AUDIT_SCHEMA_VERSION = "1.0"
_ZIP_COPY = "zip_copy"
_APKTOOL_REBUILD = "apktool_rebuild"
_SUPPORTED_STRATEGIES = {_ZIP_COPY, _APKTOOL_REBUILD}
_SUPPORTED_ACTIONS = {"unpack", "rebuild", "verify"}
_PASSWORD_OPTIONS = {"--ks-pass", "--key-pass"}
_MAX_APK_ENTRIES = 10_000
_MAX_APK_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_APK_UNCOMPRESSED_BYTES = 768 * 1024 * 1024
_MAX_APK_COMPRESSION_RATIO = 1_000
_ZIP_READ_CHUNK_BYTES = 1024 * 1024


class AndroidRebuildRunner(Protocol):
    """Command runner used by the optional apktool strategy."""

    def which(self, command: str) -> Optional[str]: ...

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any: ...


class SubprocessAndroidRebuildRunner:
    """Default subprocess adapter. It never invokes a shell."""

    def which(self, command: str) -> Optional[str]:
        return shutil.which(command)

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(item) for item in command],
            cwd=cwd,
            timeout=timeout,
            check=False,
            capture_output=True,
            text=True,
        )


class AndroidRebuildBackend(Protocol):
    """File and APK operations used by :class:`AndroidRebuildProvider`."""

    def snapshot(self, path: str | Path) -> dict[str, Any]: ...

    def inspect_apk(self, path: str | Path) -> dict[str, Any]: ...

    def copy_file(self, source: str | Path, destination: str | Path) -> None: ...

    def replace_file(self, source: str | Path, destination: str | Path) -> None: ...

    def remove_file(self, path: str | Path) -> None: ...

    def ensure_dir(self, path: str | Path) -> None: ...

    def remove_tree(self, path: str | Path) -> None: ...

    def copy_tree(self, source: str | Path, destination: str | Path) -> None: ...

    def replace_tree(self, source: str | Path, destination: str | Path) -> None: ...

    def extract_apk(self, source: str | Path, destination: str | Path) -> None: ...

    def write_json(self, path: str | Path, payload: Mapping[str, Any]) -> None: ...


class LocalAndroidRebuildBackend:
    """Pure-Python backend for snapshots, ZIP checks, and transactional copies."""

    def snapshot(self, path: str | Path) -> dict[str, Any]:
        resolved = Path(path).expanduser().resolve()
        snapshot: dict[str, Any] = {
            "path": str(resolved),
            "exists": resolved.exists(),
            "is_file": resolved.is_file(),
            "is_dir": resolved.is_dir(),
        }
        if resolved.is_dir():
            try:
                tree_hash, entry_count, total_size = _sha256_tree(resolved)
                snapshot.update(
                    {
                        "sha256": tree_hash,
                        "entry_count": entry_count,
                        "size": total_size,
                    }
                )
            except OSError as exc:
                snapshot["error"] = str(exc)
            return snapshot
        if not resolved.is_file():
            return snapshot
        try:
            snapshot.update(
                {
                    "size": resolved.stat().st_size,
                    "sha256": _sha256_file(resolved),
                }
            )
        except OSError as exc:
            snapshot["error"] = str(exc)
        return snapshot

    def inspect_apk(self, path: str | Path) -> dict[str, Any]:
        resolved = Path(path).expanduser().resolve()
        snapshot = self.snapshot(resolved)
        inspection: dict[str, Any] = {
            **snapshot,
            "is_zip": False,
            "zip_integrity": False,
            "manifest_present": False,
            "manifest_size": 0,
            "entry_count": 0,
            "duplicate_entries": [],
            "unsafe_entries": [],
            "signature": {
                "v1_present": False,
                "apk_signing_block_present": False,
                "entries": [],
            },
        }
        if not snapshot.get("is_file"):
            return inspection

        try:
            inspection["is_zip"] = zipfile.is_zipfile(resolved)
            if not inspection["is_zip"]:
                return inspection
            with zipfile.ZipFile(resolved) as archive:
                infos = archive.infolist()
                names = [item.filename for item in infos]
                counts: dict[str, int] = {}
                for name in names:
                    counts[name] = counts.get(name, 0) + 1
                duplicates = sorted(name for name, count in counts.items() if count > 1)
                unsafe_details = [
                    {"name": item.filename, "reason": reason}
                    for item in infos
                    if (reason := _archive_entry_issue(item)) is not None
                ]
                unsafe = sorted(item["name"] for item in unsafe_details)
                declared_uncompressed_bytes = sum(
                    max(0, int(item.file_size)) for item in infos
                )
                entry_limit_exceeded = len(infos) > _MAX_APK_ENTRIES
                declared_size_limit_exceeded = (
                    declared_uncompressed_bytes > _MAX_APK_UNCOMPRESSED_BYTES
                )
                manifest_infos = [item for item in infos if item.filename == "AndroidManifest.xml"]
                manifest_size = manifest_infos[0].file_size if len(manifest_infos) == 1 else 0
                signature_entries = sorted(
                    name
                    for name in names
                    if name.upper().startswith("META-INF/")
                    and name.upper().endswith((".RSA", ".DSA", ".EC", ".SF", "MANIFEST.MF"))
                )
                bad_member: Optional[str] = None
                verification_error: Optional[str] = None
                verified_uncompressed_bytes = 0
                if not (
                    duplicates
                    or unsafe
                    or entry_limit_exceeded
                    or declared_size_limit_exceeded
                ):
                    (
                        bad_member,
                        verification_error,
                        verified_uncompressed_bytes,
                    ) = _verify_zip_members(archive, infos)
                inspection.update(
                    {
                        "zip_integrity": (
                            bad_member is None
                            and verification_error is None
                            and not duplicates
                            and not unsafe
                            and not entry_limit_exceeded
                            and not declared_size_limit_exceeded
                        ),
                        "bad_member": bad_member,
                        "verification_error": verification_error,
                        "manifest_present": len(manifest_infos) == 1 and manifest_size > 0,
                        "manifest_size": manifest_size,
                        "entry_count": len(infos),
                        "entry_limit_exceeded": entry_limit_exceeded,
                        "declared_uncompressed_bytes": declared_uncompressed_bytes,
                        "verified_uncompressed_bytes": verified_uncompressed_bytes,
                        "declared_size_limit_exceeded": declared_size_limit_exceeded,
                        "duplicate_entries": duplicates,
                        "unsafe_entries": unsafe,
                        "unsafe_entry_details": unsafe_details,
                        "limits": {
                            "max_entries": _MAX_APK_ENTRIES,
                            "max_member_bytes": _MAX_APK_MEMBER_BYTES,
                            "max_uncompressed_bytes": _MAX_APK_UNCOMPRESSED_BYTES,
                            "max_compression_ratio": _MAX_APK_COMPRESSION_RATIO,
                        },
                        "signature": {
                            "v1_present": any(
                                name.upper().endswith((".RSA", ".DSA", ".EC"))
                                for name in signature_entries
                            ),
                            "apk_signing_block_present": _has_apk_signing_block(resolved),
                            "entries": signature_entries,
                        },
                    }
                )
        except (
            OSError,
            RuntimeError,
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
            NotImplementedError,
        ) as exc:
            inspection["error"] = str(exc)
        return inspection

    def copy_file(self, source: str | Path, destination: str | Path) -> None:
        source_path = Path(source)
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, destination_path)

    def replace_file(self, source: str | Path, destination: str | Path) -> None:
        source_path = Path(source)
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source_path, destination_path)

    def remove_file(self, path: str | Path) -> None:
        Path(path).unlink(missing_ok=True)

    def ensure_dir(self, path: str | Path) -> None:
        Path(path).mkdir(parents=True, exist_ok=True)

    def remove_tree(self, path: str | Path) -> None:
        resolved = Path(path)
        if resolved.exists():
            shutil.rmtree(resolved)

    def copy_tree(self, source: str | Path, destination: str | Path) -> None:
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(Path(source), destination_path, symlinks=True)

    def replace_tree(self, source: str | Path, destination: str | Path) -> None:
        source_path = Path(source)
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        if destination_path.exists():
            shutil.rmtree(destination_path)
        shutil.move(str(source_path), str(destination_path))

    def extract_apk(self, source: str | Path, destination: str | Path) -> None:
        destination_path = Path(destination).expanduser().resolve()
        if destination_path.exists():
            raise FileExistsError(f"unpack destination already exists: {destination_path}")
        destination_path.mkdir(parents=True)
        try:
            with zipfile.ZipFile(Path(source)) as archive:
                infos = archive.infolist()
                if len(infos) > _MAX_APK_ENTRIES:
                    raise ValueError(
                        f"APK ZIP entry count exceeds limit {_MAX_APK_ENTRIES}"
                    )
                names = [item.filename for item in infos]
                if len(names) != len(set(names)):
                    raise ValueError("APK contains duplicate ZIP entries")
                declared_uncompressed_bytes = sum(
                    max(0, int(item.file_size)) for item in infos
                )
                if declared_uncompressed_bytes > _MAX_APK_UNCOMPRESSED_BYTES:
                    raise ValueError(
                        "APK declared uncompressed size exceeds extraction limit "
                        f"{_MAX_APK_UNCOMPRESSED_BYTES}"
                    )
                extracted_bytes = 0
                for info in infos:
                    entry_issue = _archive_entry_issue(info)
                    if entry_issue:
                        raise ValueError(
                            f"unsafe APK ZIP entry {info.filename}: {entry_issue}"
                        )
                    relative = PurePosixPath(info.filename)
                    output = destination_path.joinpath(*relative.parts)
                    if not _is_relative_to(output.resolve(), destination_path):
                        raise ValueError(f"unsafe APK ZIP entry: {info.filename}")
                    if info.is_dir():
                        output.mkdir(parents=True, exist_ok=True)
                        continue
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source_handle, output.open("wb") as output_handle:
                        member_bytes = 0
                        while True:
                            chunk = source_handle.read(_ZIP_READ_CHUNK_BYTES)
                            if not chunk:
                                break
                            member_bytes += len(chunk)
                            extracted_bytes += len(chunk)
                            if member_bytes > _MAX_APK_MEMBER_BYTES:
                                raise ValueError(
                                    f"APK ZIP member exceeds extraction limit: {info.filename}"
                                )
                            if extracted_bytes > _MAX_APK_UNCOMPRESSED_BYTES:
                                raise ValueError(
                                    "APK extracted bytes exceed total extraction limit"
                                )
                            output_handle.write(chunk)
                        if member_bytes != info.file_size:
                            raise ValueError(
                                f"APK ZIP member size mismatch: {info.filename}"
                            )
        except Exception:
            shutil.rmtree(destination_path, ignore_errors=True)
            raise

    def write_json(self, path: str | Path, payload: Mapping[str, Any]) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.tmp")
        temporary.write_text(
            json.dumps(_json_value(payload), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, destination)


class AndroidRebuildProvider:
    """Unpack, rebuild, and verify APKs with auditable, reversible operations."""

    capability_name = "android_rebuild"
    provider_name = "local_android_rebuild"
    priority = 10
    supported_actions = ("unpack", "rebuild", "verify")
    supported_strategies = (_ZIP_COPY, _APKTOOL_REBUILD)
    parameter_contract = {
        "common": ("strategy", "artifact_dir", "timeout"),
        "unpack": (
            "unpack_dir",
            "work_dir",
            "apktool",
            "apktool_path",
            "keep_work_dir",
        ),
        "rebuild": (
            "out_path",
            "output_path",
            "work_dir",
            "project_dir",
            "decompiled_dir",
            "decoded_dir",
            "apktool",
            "apktool_path",
            "apksigner",
            "apksigner_path",
            "keystore",
            "keystore_path",
            "ks",
            "key_alias",
            "ks_key_alias",
            "alias",
            "ks_pass",
            "keystore_password",
            "key_pass",
            "key_password",
            "key",
            "key_path",
            "private_key",
            "cert",
            "cert_path",
            "certificate",
            "apksigner_args",
            "keep_work_dir",
        ),
        "verify": ("verify_signature", "apksigner", "apksigner_path"),
    }

    def __init__(
        self,
        runner: Optional[AndroidRebuildRunner] = None,
        backend: Optional[AndroidRebuildBackend] = None,
        *,
        default_strategy: str = _ZIP_COPY,
        timeout: float = 300.0,
    ) -> None:
        self.runner: Any = runner or SubprocessAndroidRebuildRunner()
        self.backend: AndroidRebuildBackend = backend or LocalAndroidRebuildBackend()
        normalized_strategy = _normalize_strategy(default_strategy)
        self.default_strategy = normalized_strategy or _ZIP_COPY
        self.timeout = max(1.0, float(timeout))
        self._signing_secrets: dict[str, dict[str, Any]] = {}

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        action = str(request.action or "").strip().lower().replace("-", "_")
        return request.capability == self.capability_name and action in _SUPPORTED_ACTIONS

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        backend = self._select_backend(context)
        action = _normalize_action(request.action)
        if action not in _SUPPORTED_ACTIONS:
            raise ValueError(
                f"unsupported android_rebuild action: {request.action}; "
                f"expected one of {', '.join(sorted(_SUPPORTED_ACTIONS))}"
            )
        source_path = _request_source_path(request)
        session_id = request.session_id or "android-rebuild-session"
        source_snapshot = backend.snapshot(source_path)
        source_is_project = action == "rebuild" and bool(source_snapshot.get("is_dir"))
        strategy = _request_strategy(
            request,
            self.default_strategy,
            source_is_project=source_is_project,
        )
        output_path = _request_output_path(request, source_path, context=context)
        unpack_dir = _request_unpack_dir(request, source_path, context=context)
        destination_path = output_path if action == "rebuild" else unpack_dir
        artifact_dir = _request_artifact_dir(
            request,
            destination_path,
            context=context,
        )
        work_dir = _request_path(
            request.params,
            ("work_dir",),
            default=artifact_dir / "work" / _safe_segment(session_id),
        )
        work_dir_existed = bool(backend.snapshot(work_dir).get("exists"))
        project_dir_value = _first_value(
            request.params,
            ("project_dir", "decompiled_dir", "decoded_dir"),
        )
        if project_dir_value in (None, "") and source_is_project:
            project_dir_value = source_path
        project_dir = (
            Path(str(project_dir_value)).expanduser().resolve()
            if project_dir_value not in (None, "")
            else None
        )
        decoded_dir = project_dir or (work_dir / "decoded")
        unsigned_path = work_dir / "unsigned.apk"
        temporary_output = output_path.with_name(
            f".{output_path.stem}.{_safe_segment(session_id)}.tmp.apk"
        )
        temporary_unpack = work_dir / "unpacked"
        verify_path = artifact_dir / f"{action}_verify.json"
        audit_path = artifact_dir / f"{action}_audit.json"
        backup_name = output_path.name if action == "rebuild" else unpack_dir.name
        backup_path = artifact_dir / "rollback" / (
            f"{_safe_segment(session_id)}-{backup_name}.bak"
        )
        source_inspection = (
            {**source_snapshot, "kind": "apktool_project"}
            if source_is_project
            else backend.inspect_apk(source_path)
        )
        output_snapshot = backend.snapshot(output_path)
        unpack_snapshot = backend.snapshot(unpack_dir)
        signing_private, signing_public = _signing_configuration(request.params)
        if action == "rebuild" and strategy == _APKTOOL_REBUILD:
            self._signing_secrets[session_id] = signing_private
        configured_tools = {
            "apktool": str(
                _first_value(request.params, ("apktool", "apktool_path")) or "apktool"
            ),
            "apksigner": str(
                _first_value(request.params, ("apksigner", "apksigner_path"))
                or "apksigner"
            ),
        }
        timeout = _bounded_timeout(request.params.get("timeout"), self.timeout)
        verify_signature = _coerce_bool(
            request.params.get("verify_signature"),
            default=action == "verify" and strategy == _APKTOOL_REBUILD,
        )
        capability_boundary = _android_capability_boundary(
            action=action,
            strategy=strategy,
            verify_signature=verify_signature,
        )
        parameters = {
            "strategy": strategy,
            "source_kind": "apktool_project" if source_is_project else "apk",
            "source_path": str(source_path),
            "artifact_dir": str(artifact_dir),
            "verify_path": str(verify_path),
            "audit_path": str(audit_path),
            "work_dir": str(work_dir),
            "tools": configured_tools,
            "timeout": timeout,
            "keep_work_dir": _coerce_bool(
                request.params.get("keep_work_dir"), default=False
            ),
            "work_dir_existed": work_dir_existed,
        }
        if action == "rebuild":
            parameters.update(
                {
                    "out_path": str(output_path),
                    "backup_path": str(backup_path),
                    "decoded_dir": str(decoded_dir),
                    "project_dir": str(project_dir) if project_dir is not None else None,
                    "unsigned_path": str(unsigned_path),
                    "temporary_output": str(temporary_output),
                    "signing": signing_public,
                }
            )
        elif action == "unpack":
            parameters.update(
                {
                    "unpack_dir": str(unpack_dir),
                    "backup_path": str(backup_path),
                    "temporary_unpack": str(temporary_unpack),
                }
            )
        else:
            parameters["verify_signature"] = verify_signature
        parameters_payload = _with_capability_boundary(
            parameters,
            capability_boundary,
        )
        before_snapshot = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "source": source_snapshot,
            "source_project" if source_is_project else "source_apk": source_inspection,
            "sha256": source_snapshot.get("sha256"),
            "source_sha256": source_snapshot.get("sha256"),
        }
        if action == "rebuild":
            before_snapshot.update(
                {
                    "output": output_snapshot,
                    "output_sha256": output_snapshot.get("sha256"),
                }
            )
            output_existed = bool(output_snapshot.get("exists"))
            rollback_plan = {
                "supported": True,
                "mode": "restore_output" if output_existed else "delete_output",
                "output_path": str(output_path),
                "output_existed": output_existed,
                "prior_output_sha256": output_snapshot.get("sha256"),
                "backup_path": str(backup_path) if output_existed else None,
                "completed": False,
            }
        elif action == "unpack":
            before_snapshot["unpack"] = unpack_snapshot
            unpack_existed = bool(unpack_snapshot.get("exists"))
            rollback_plan = {
                "supported": True,
                "mode": "restore_unpack" if unpack_existed else "delete_unpack",
                "output_path": str(unpack_dir),
                "output_existed": unpack_existed,
                "prior_output_sha256": unpack_snapshot.get("sha256"),
                "backup_path": str(backup_path) if unpack_existed else None,
                "completed": False,
            }
        else:
            rollback_plan = _non_execution_rollback_plan(
                "verify does not modify the target APK"
            )

        steps = [
            {
                "step": "verify_target_project" if source_is_project else "verify_target_apk",
                "status": "planned",
            }
        ]
        if action == "rebuild":
            steps.append({"step": "verify_output_isolation", "status": "planned"})
            if strategy == _APKTOOL_REBUILD:
                if project_dir is None:
                    steps.append({"step": "apktool_decode", "status": "planned"})
                steps.extend(
                    [
                        {"step": "apktool_rebuild", "status": "planned"},
                        {"step": "apksigner_sign", "status": "planned"},
                        {"step": "apksigner_verify", "status": "planned"},
                    ]
                )
            else:
                steps.append({"step": "zip_copy", "status": "planned"})
            steps.extend(
                [
                    {"step": "verify_rebuilt_apk", "status": "planned"},
                    {"step": "write_rebuild_audit", "status": "planned"},
                ]
            )
        elif action == "unpack":
            steps.append({"step": "verify_unpack_isolation", "status": "planned"})
            steps.append(
                {
                    "step": "apktool_decode" if strategy == _APKTOOL_REBUILD else "zip_unpack",
                    "status": "planned",
                }
            )
            steps.extend(
                [
                    {"step": "verify_unpacked_manifest", "status": "planned"},
                    {"step": "write_unpack_audit", "status": "planned"},
                ]
            )
        else:
            if verify_signature:
                steps.append({"step": "apksigner_verify", "status": "planned"})
            steps.append({"step": "write_verify_audit", "status": "planned"})
        provenance = _with_capability_boundary(
            {
                **_json_mapping(request.provenance),
                "audit_schema_version": _AUDIT_SCHEMA_VERSION,
                "provider": self.provider_name,
                "requested_action": request.action,
                "action": action,
                "strategy": strategy,
                "source_kind": "apktool_project" if source_is_project else "apk",
                "source_path": str(source_path),
                "planned_source_sha256": source_snapshot.get("sha256"),
                "declared_source_sha256": request.target.sha256,
                "output_path": str(output_path) if action == "rebuild" else None,
                "unpack_dir": str(unpack_dir) if action == "unpack" else None,
                "project_dir": str(project_dir) if project_dir is not None else None,
                "toolchain": configured_tools
                if strategy == _APKTOOL_REBUILD or verify_signature
                else {"python": "zipfile"},
            },
            capability_boundary,
        )
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=action,
            parameters=parameters_payload,
            steps=steps,
            precondition_hash=source_snapshot.get("sha256"),
            before_snapshot=before_snapshot,
            rollback_plan=_prune(rollback_plan),
            provenance=provenance,
        )

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        backend = self._select_backend(context)
        runner = self._select_runner(context)
        checks: list[dict[str, Any]] = []
        warnings: list[str] = []
        errors: list[str] = []
        action = _normalize_action(plan.action)
        strategy = _normalize_strategy(plan.parameters.get("strategy"))
        source_path = _plan_path(plan, "source_path", plan.target.path)
        source_snapshot = backend.snapshot(source_path)
        source_is_project = (
            str(plan.parameters.get("source_kind") or "") == "apktool_project"
            or bool(source_snapshot.get("is_dir"))
        )
        source_inspection = (
            {**source_snapshot, "kind": "apktool_project"}
            if source_is_project
            else backend.inspect_apk(source_path)
        )

        _add_check(
            checks,
            errors,
            name="android_rebuild_action",
            ok=action in _SUPPORTED_ACTIONS,
            error=f"unsupported android_rebuild action: {plan.action}",
            action=action,
            supported=sorted(_SUPPORTED_ACTIONS),
        )

        strategy_ok = strategy in _SUPPORTED_STRATEGIES
        _add_check(
            checks,
            errors,
            name="android_rebuild_strategy",
            ok=strategy_ok,
            error=f"unsupported Android strategy: {strategy or plan.parameters.get('strategy')}",
            strategy=strategy,
            supported=sorted(_SUPPORTED_STRATEGIES),
        )

        planned_source = str(plan.provenance.get("source_path") or "")
        target_source = str(Path(plan.target.path or "").expanduser().resolve())
        source_identity_ok = (
            bool(plan.target.path)
            and _paths_equal(source_path, target_source)
            and (not planned_source or _paths_equal(source_path, planned_source))
        )
        _add_check(
            checks,
            errors,
            name="target_path_identity",
            ok=source_identity_ok,
            error="planned APK path no longer matches the target identity",
            expected=target_source,
            planned=planned_source,
            actual=str(source_path),
        )

        if source_is_project:
            project_manifest = backend.snapshot(source_path / "AndroidManifest.xml")
            project_ok = (
                action == "rebuild"
                and bool(source_snapshot.get("is_dir"))
                and bool(project_manifest.get("is_file"))
                and int(project_manifest.get("size") or 0) > 0
            )
            _add_check(
                checks,
                errors,
                name="apktool_project_target",
                ok=project_ok,
                error="decoded Android project target must contain a non-empty AndroidManifest.xml",
                path=str(source_path),
                manifest=project_manifest,
            )
            _add_check(
                checks,
                errors,
                name="project_rebuild_strategy",
                ok=strategy == _APKTOOL_REBUILD,
                error="decoded Android project targets require strategy apktool_rebuild",
                strategy=strategy,
            )
        else:
            file_ok = bool(source_snapshot.get("is_file")) and source_path.suffix.lower() == ".apk"
            _add_check(
                checks,
                errors,
                name="apk_file",
                ok=file_ok,
                error="Android rebuild target must be an existing .apk file",
                path=str(source_path),
                snapshot=source_snapshot,
            )
            zip_ok = bool(source_inspection.get("is_zip")) and bool(
                source_inspection.get("zip_integrity")
            )
            _add_check(
                checks,
                errors,
                name="apk_zip_integrity",
                ok=zip_ok,
                error="target APK is not a complete, safe ZIP archive",
                bad_member=source_inspection.get("bad_member"),
                duplicate_entries=source_inspection.get("duplicate_entries"),
                unsafe_entries=source_inspection.get("unsafe_entries"),
            )
            manifest_ok = bool(source_inspection.get("manifest_present"))
            _add_check(
                checks,
                errors,
                name="android_manifest",
                ok=manifest_ok,
                error="target APK does not contain a non-empty root AndroidManifest.xml",
                size=source_inspection.get("manifest_size"),
            )

        actual_hash = source_snapshot.get("sha256")
        expected_hash = plan.precondition_hash
        hash_ok = _valid_sha256(expected_hash) and _hashes_equal(actual_hash, expected_hash)
        _add_check(
            checks,
            errors,
            name="target_precondition_hash",
            ok=hash_ok,
            error="target APK does not match the planned SHA-256 precondition",
            expected=expected_hash,
            actual=actual_hash,
        )
        declared_hash = plan.provenance.get("declared_source_sha256") or plan.target.sha256
        if declared_hash:
            declared_ok = _valid_sha256(declared_hash) and _hashes_equal(
                actual_hash, declared_hash
            )
            _add_check(
                checks,
                errors,
                name="declared_target_hash",
                ok=declared_ok,
                error="declared target SHA-256 does not match the APK",
                expected=declared_hash,
                actual=actual_hash,
            )

        if action == "verify":
            artifact_paths = [
                _plan_path(plan, "verify_path"),
                _plan_path(plan, "audit_path"),
            ]
            artifact_isolation = all(
                not _paths_equal(path, source_path) for path in artifact_paths
            )
            _add_check(
                checks,
                errors,
                name="artifact_path_isolation",
                ok=artifact_isolation,
                error="verify artifact paths must not overwrite the target APK",
            )
            artifact_parent_ok = all(
                _writable_destination_parent(path) for path in artifact_paths
            )
            _add_check(
                checks,
                errors,
                name="artifact_parent_writable",
                ok=artifact_parent_ok,
                error="verify artifact parent is not writable",
            )
            if _coerce_bool(plan.parameters.get("verify_signature"), default=False):
                details = _resolve_named_tools(
                    plan,
                    runner,
                    ("apksigner",),
                    probe=True,
                    cwd=source_path.parent,
                    timeout=min(self.timeout, 15.0),
                )["apksigner"]
                checks.append(
                    {
                        "name": "apksigner_available",
                        "status": "ok" if details["available"] else "unavailable",
                        **details,
                    }
                )
                if not details["available"]:
                    warnings.append("apksigner is unavailable; signature verification cannot execute")
            checks.append(_capability_boundary_check(plan, checks))
            return CapabilityValidation(
                capability=plan.capability,
                provider=plan.provider,
                session_id=plan.session_id,
                ok=not errors,
                checks=checks,
                warnings=_deduplicate(warnings),
                errors=_deduplicate(errors),
            )

        if action == "unpack":
            unpack_dir = _plan_path(plan, "unpack_dir")
            unpack_snapshot = backend.snapshot(unpack_dir)
            unpack_isolated = (
                not _paths_equal(source_path, unpack_dir)
                and not _path_contains(unpack_dir, source_path)
            )
            _add_check(
                checks,
                errors,
                name="unpack_path_isolation",
                ok=unpack_isolated,
                error="unpack directory must not contain or overwrite the original APK",
                source_path=str(source_path),
                unpack_dir=str(unpack_dir),
            )
            output_type_ok = not unpack_snapshot.get("is_file")
            _add_check(
                checks,
                errors,
                name="unpack_path_type",
                ok=output_type_ok,
                error="unpack destination must be a directory path",
                unpack_dir=str(unpack_dir),
            )
            output_state_ok = _same_snapshot(
                plan.before_snapshot.get("unpack"), unpack_snapshot
            )
            _add_check(
                checks,
                errors,
                name="unpack_precondition",
                ok=output_state_ok,
                error="unpack destination changed after planning",
                expected=plan.before_snapshot.get("unpack"),
                actual=unpack_snapshot,
            )
            _add_check(
                checks,
                errors,
                name="unpack_parent_writable",
                ok=_writable_destination_parent(unpack_dir),
                error="unpack destination parent is not writable",
                unpack_dir=str(unpack_dir),
            )
            artifact_paths = [
                _plan_path(plan, "verify_path"),
                _plan_path(plan, "audit_path"),
                _plan_path(plan, "backup_path"),
                _plan_path(plan, "temporary_unpack"),
            ]
            artifacts_isolated = all(
                not _paths_equal(path, source_path)
                and not _paths_equal(path, unpack_dir)
                and not _path_contains(path, source_path)
                and not _path_contains(unpack_dir, path)
                for path in artifact_paths
            )
            _add_check(
                checks,
                errors,
                name="artifact_path_isolation",
                ok=artifacts_isolated,
                error="unpack audit, backup, and temporary paths must be isolated",
            )
            backup_path = _plan_path(plan, "backup_path")
            _add_check(
                checks,
                errors,
                name="rollback_backup_path",
                ok=not backend.snapshot(backup_path).get("exists"),
                error="unpack rollback backup path already exists",
                path=str(backup_path),
            )
            temporary_unpack = _plan_path(plan, "temporary_unpack")
            _add_check(
                checks,
                errors,
                name="temporary_unpack_path",
                ok=not backend.snapshot(temporary_unpack).get("exists"),
                error="temporary unpack path already exists",
                path=str(temporary_unpack),
            )
            if strategy == _APKTOOL_REBUILD:
                details = _resolve_named_tools(
                    plan,
                    runner,
                    ("apktool",),
                    probe=True,
                    cwd=source_path.parent,
                    timeout=min(self.timeout, 15.0),
                )["apktool"]
                checks.append(
                    {
                        "name": "apktool_available",
                        "status": "ok" if details["available"] else "unavailable",
                        **details,
                    }
                )
                if not details["available"]:
                    warnings.append("apktool is unavailable; unpack cannot execute")
            checks.append(_capability_boundary_check(plan, checks))
            return CapabilityValidation(
                capability=plan.capability,
                provider=plan.provider,
                session_id=plan.session_id,
                ok=not errors,
                checks=checks,
                warnings=_deduplicate(warnings),
                errors=_deduplicate(errors),
            )

        output_path = _plan_path(plan, "out_path")
        output_snapshot = backend.snapshot(output_path)

        output_isolated = not _paths_equal(source_path, output_path) and not (
            source_is_project and _path_contains(source_path, output_path)
        )
        _add_check(
            checks,
            errors,
            name="output_path_isolation",
            ok=output_isolated,
            error="rebuild output path must not overwrite the original APK",
            source_path=str(source_path),
            output_path=str(output_path),
        )
        output_type_ok = output_path.suffix.lower() == ".apk" and not output_snapshot.get(
            "is_dir"
        )
        _add_check(
            checks,
            errors,
            name="output_path_type",
            ok=output_type_ok,
            error="rebuild output must be an .apk file path, not a directory",
            output_path=str(output_path),
            exists=output_snapshot.get("exists"),
        )
        output_state_ok = _same_snapshot(
            plan.before_snapshot.get("output"), output_snapshot
        )
        _add_check(
            checks,
            errors,
            name="output_precondition",
            ok=output_state_ok,
            error="rebuild output changed after planning",
            expected=plan.before_snapshot.get("output"),
            actual=output_snapshot,
        )
        parent_ok = _writable_destination_parent(output_path)
        _add_check(
            checks,
            errors,
            name="output_parent_writable",
            ok=parent_ok,
            error="rebuild output parent is not writable",
            output_path=str(output_path),
        )

        artifact_paths = [
            _plan_path(plan, "verify_path"),
            _plan_path(plan, "audit_path"),
            _plan_path(plan, "backup_path"),
            _plan_path(plan, "temporary_output"),
        ]
        artifacts_isolated = all(
            not _paths_equal(path, source_path)
            and not _paths_equal(path, output_path)
            and not (source_is_project and _path_contains(source_path, path))
            for path in artifact_paths
        )
        _add_check(
            checks,
            errors,
            name="artifact_path_isolation",
            ok=artifacts_isolated,
            error="rebuild audit, backup, and temporary paths must be isolated from APK paths",
        )
        backup_path = _plan_path(plan, "backup_path")
        backup_snapshot = backend.snapshot(backup_path)
        backup_ok = not backup_snapshot.get("exists")
        _add_check(
            checks,
            errors,
            name="rollback_backup_path",
            ok=backup_ok,
            error="rollback backup path already exists",
            path=str(backup_path),
        )
        temporary_path = _plan_path(plan, "temporary_output")
        temporary_ok = not backend.snapshot(temporary_path).get("exists")
        _add_check(
            checks,
            errors,
            name="temporary_output_path",
            ok=temporary_ok,
            error="temporary rebuild output already exists",
            path=str(temporary_path),
        )

        source_signature = _json_mapping(source_inspection.get("signature"))
        if strategy == _ZIP_COPY:
            checks.append(
                {
                    "name": "signing_integrity",
                    "status": "ok",
                    "mode": "byte_preserving_copy",
                    "source_signed": bool(
                        source_signature.get("v1_present")
                        or source_signature.get("apk_signing_block_present")
                    ),
                    "reason": "zip_copy preserves every source byte and therefore any existing signature",
                }
            )
        elif strategy == _APKTOOL_REBUILD:
            signing_errors = _signing_configuration_errors(plan.parameters.get("signing"))
            tools = _resolve_toolchain(
                plan,
                runner,
                probe=not signing_errors,
                cwd=source_path if source_is_project else source_path.parent,
                timeout=min(self.timeout, 15.0),
            )
            for name in ("apktool", "apksigner"):
                details = tools[name]
                checks.append(
                    {
                        "name": f"{name}_available",
                        "status": "ok" if details["available"] else "unavailable",
                        **details,
                    }
                )
                if not details["available"]:
                    warnings.append(f"{name} is unavailable; apktool_rebuild cannot execute")
            if signing_errors:
                checks.append(
                    {
                        "name": "signing_configuration",
                        "status": "failed",
                        "mode": _json_mapping(plan.parameters.get("signing")).get("mode"),
                        "errors": signing_errors,
                    }
                )
                errors.extend(signing_errors)
            elif all(item["available"] for item in tools.values()):
                checks.append(
                    {
                        "name": "signing_configuration",
                        "status": "ok",
                        "mode": _json_mapping(plan.parameters.get("signing")).get("mode"),
                        "errors": [],
                    }
                )
            else:
                checks.append(
                    {
                        "name": "signing_configuration",
                        "status": "unavailable",
                        "reason": "signing configuration is deferred until the external toolchain is available",
                    }
                )
            project_dir = plan.parameters.get("project_dir")
            if project_dir:
                project_path = Path(str(project_dir)).expanduser().resolve()
                project_ok = project_path.is_dir() and (
                    project_path / "AndroidManifest.xml"
                ).is_file()
                _add_check(
                    checks,
                    errors,
                    name="apktool_project",
                    ok=project_ok,
                    error="provided apktool project must contain AndroidManifest.xml",
                    path=str(project_path),
                )

        checks.append(_capability_boundary_check(plan, checks))
        return CapabilityValidation(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            ok=not errors,
            checks=checks,
            warnings=_deduplicate(warnings),
            errors=_deduplicate(errors),
        )

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        action = _normalize_action(plan.action)
        if action == "unpack":
            return self._execute_unpack(plan, context=context)
        if action == "verify":
            return self._execute_verify(plan, context=context)
        backend = self._select_backend(context)
        runner = self._select_runner(context)
        validation = self.validate(plan, context=context)
        strategy = _normalize_strategy(plan.parameters.get("strategy"))
        source_path = _plan_path(plan, "source_path", plan.target.path)
        output_path = _plan_path(plan, "out_path")
        temporary_output = _plan_path(plan, "temporary_output")
        before_snapshot = {
            **_json_mapping(plan.before_snapshot),
            "execution_source": backend.snapshot(source_path),
            "execution_output": backend.snapshot(output_path),
            "validation": validation.to_dict(),
        }
        command_records: list[dict[str, Any]] = []
        signing: dict[str, Any] = {}

        unavailable_checks = [
            item
            for item in validation.checks
            if item.get("name") in {"apktool_available", "apksigner_available"}
            and item.get("status") == "unavailable"
        ]
        if strategy == _APKTOOL_REBUILD and unavailable_checks:
            reason = "; ".join(
                str(item.get("reason") or f"{item.get('name')} unavailable")
                for item in unavailable_checks
            )
            self._signing_secrets.pop(plan.session_id, None)
            return self._execution_result(
                plan,
                validation=validation,
                status="unavailable",
                before_snapshot=before_snapshot,
                after_snapshot={
                    "source": backend.snapshot(source_path),
                    "output": backend.snapshot(output_path),
                    "side_effects": False,
                },
                rollback_plan=_non_execution_rollback_plan(reason),
                command_records=command_records,
                signing={"status": "unavailable", "reason": reason},
                error=reason,
                backend=backend,
            )
        if not validation.ok:
            reason = "; ".join(validation.errors) or "Android rebuild validation failed"
            self._signing_secrets.pop(plan.session_id, None)
            return self._execution_result(
                plan,
                validation=validation,
                status="failed",
                before_snapshot=before_snapshot,
                after_snapshot={
                    "source": backend.snapshot(source_path),
                    "output": backend.snapshot(output_path),
                    "side_effects": False,
                },
                rollback_plan=_non_execution_rollback_plan(reason),
                command_records=command_records,
                signing={"status": "not_attempted"},
                error=reason,
                backend=backend,
            )

        try:
            backend.ensure_dir(output_path.parent)
            if strategy == _ZIP_COPY:
                backend.copy_file(source_path, temporary_output)
                signing = {
                    "status": "preserved",
                    "mode": "byte_preserving_copy",
                    "verified_by": "identical_sha256",
                }
            else:
                command_records, signing = self._execute_apktool_rebuild(
                    plan,
                    runner=runner,
                    backend=backend,
                    source_path=source_path,
                    temporary_output=temporary_output,
                )

            temporary_inspection = backend.inspect_apk(temporary_output)
            output_valid = bool(temporary_inspection.get("zip_integrity")) and bool(
                temporary_inspection.get("manifest_present")
            )
            if not output_valid:
                raise RuntimeError("rebuilt APK failed ZIP or AndroidManifest.xml verification")
            if strategy == _ZIP_COPY and not _hashes_equal(
                temporary_inspection.get("sha256"), plan.precondition_hash
            ):
                raise RuntimeError("zip_copy output differs from the source APK")
            current_source = backend.snapshot(source_path)
            if not _hashes_equal(current_source.get("sha256"), plan.precondition_hash):
                raise RuntimeError("source APK changed during rebuild execution")

            current_output = backend.snapshot(output_path)
            if not _same_snapshot(plan.before_snapshot.get("output"), current_output):
                raise RuntimeError("rebuild output changed during execution")
            rollback_plan = dict(plan.rollback_plan or {})
            backup_path = _plan_path(plan, "backup_path")
            if current_output.get("exists"):
                backend.ensure_dir(backup_path.parent)
                backend.copy_file(output_path, backup_path)
            try:
                backend.replace_file(temporary_output, output_path)
            except Exception:
                if current_output.get("exists") and backend.snapshot(backup_path).get("is_file"):
                    backend.copy_file(backup_path, output_path)
                raise

            output_inspection = backend.inspect_apk(output_path)
            final_ok = bool(output_inspection.get("zip_integrity")) and bool(
                output_inspection.get("manifest_present")
            )
            if not final_ok:
                self._restore_failed_commit(
                    backend,
                    output_path=output_path,
                    backup_path=backup_path,
                    output_existed=bool(current_output.get("exists")),
                )
                raise RuntimeError("committed APK failed final ZIP integrity verification")

            rollback_plan.update(
                {
                    "supported": True,
                    "mode": "restore_output"
                    if current_output.get("exists")
                    else "delete_output",
                    "output_path": str(output_path),
                    "output_existed": bool(current_output.get("exists")),
                    "prior_output_sha256": current_output.get("sha256"),
                    "backup_path": str(backup_path)
                    if current_output.get("exists")
                    else None,
                    "output_sha256": output_inspection.get("sha256"),
                    "completed": False,
                }
            )
            after_snapshot = {
                "source": current_source,
                "output": output_inspection,
                "sha256": output_inspection.get("sha256"),
                "source_sha256": current_source.get("sha256"),
                "output_sha256": output_inspection.get("sha256"),
                "zip_integrity": output_inspection.get("zip_integrity"),
                "manifest_present": output_inspection.get("manifest_present"),
                "side_effects": True,
            }
            result = self._execution_result(
                plan,
                validation=validation,
                status="ok",
                before_snapshot=before_snapshot,
                after_snapshot=after_snapshot,
                rollback_plan=_prune(rollback_plan),
                command_records=command_records,
                signing=signing,
                error=None,
                backend=backend,
            )
            return result
        except Exception as exc:
            backend.remove_file(temporary_output)
            recorded_commands = getattr(exc, "command_records", None)
            if recorded_commands:
                command_records = list(recorded_commands)
            else:
                failed_record = getattr(exc, "command_record", None)
                if failed_record:
                    command_records.append(failed_record)
            reason = str(exc) or exc.__class__.__name__
            return self._execution_result(
                plan,
                validation=validation,
                status="failed",
                before_snapshot=before_snapshot,
                after_snapshot={
                    "source": backend.snapshot(source_path),
                    "output": backend.snapshot(output_path),
                    "side_effects": False,
                },
                rollback_plan=_non_execution_rollback_plan(reason),
                command_records=command_records,
                signing=signing or {"status": "failed", "reason": reason},
                error=reason,
                backend=backend,
            )
        finally:
            self._signing_secrets.pop(plan.session_id, None)
            if not bool(plan.parameters.get("keep_work_dir")) and not bool(
                plan.parameters.get("work_dir_existed")
            ):
                work_dir = _plan_path(plan, "work_dir")
                project_dir = plan.parameters.get("project_dir")
                if not project_dir or not _paths_equal(work_dir, project_dir):
                    backend.remove_tree(work_dir)

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        backend = self._select_backend(context)
        rollback_plan = dict(result.rollback_plan or {})
        if not rollback_plan.get("supported") or not bool(
            result.after_snapshot.get("side_effects")
        ):
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=True,
                restored=False,
                details={
                    "status": "not_required",
                    "reason": f"{result.action} produced no reversible output",
                },
            )

        output_path = Path(str(rollback_plan.get("output_path") or "")).expanduser().resolve()
        expected_output_hash = rollback_plan.get("output_sha256")
        current_output = backend.snapshot(output_path)
        if current_output.get("exists") and not _hashes_equal(
            current_output.get("sha256"), expected_output_hash
        ):
            details = {
                "status": "failed",
                "mode": rollback_plan.get("mode"),
                "output_path": str(output_path),
                "expected_output_sha256": expected_output_hash,
                "actual_output_sha256": current_output.get("sha256"),
                "error": "rebuilt output changed after execution; refusing rollback",
            }
            self._record_rollback(result, details, backend=backend)
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=False,
                restored=False,
                details=details,
            )

        mode = str(rollback_plan.get("mode") or "")
        details: dict[str, Any] = {
            "status": "failed",
            "mode": mode,
            "output_path": str(output_path),
            "expected_output_sha256": expected_output_hash,
        }
        restored = False
        try:
            if mode == "delete_output":
                backend.remove_file(output_path)
                restored = not backend.snapshot(output_path).get("exists")
                details.update({"deleted": restored, "restored_absence": restored})
            elif mode == "delete_unpack":
                backend.remove_tree(output_path)
                restored = not backend.snapshot(output_path).get("exists")
                details.update({"deleted": restored, "restored_absence": restored})
            elif mode == "restore_output":
                backup_value = rollback_plan.get("backup_path")
                if not backup_value:
                    raise RuntimeError("rollback backup path is missing")
                backup_path = Path(str(backup_value)).expanduser().resolve()
                backup_snapshot = backend.snapshot(backup_path)
                expected_prior_hash = rollback_plan.get("prior_output_sha256")
                if not backup_snapshot.get("is_file") or not _hashes_equal(
                    backup_snapshot.get("sha256"), expected_prior_hash
                ):
                    raise RuntimeError("rollback backup is missing or does not match its planned hash")
                backend.replace_file(backup_path, output_path)
                restored_snapshot = backend.snapshot(output_path)
                restored = _hashes_equal(
                    restored_snapshot.get("sha256"), expected_prior_hash
                )
                details.update(
                    {
                        "backup_path": str(backup_path),
                        "prior_output_sha256": expected_prior_hash,
                        "restored_sha256": restored_snapshot.get("sha256"),
                    }
                )
            elif mode == "restore_unpack":
                backup_value = rollback_plan.get("backup_path")
                if not backup_value:
                    raise RuntimeError("unpack rollback backup path is missing")
                backup_path = Path(str(backup_value)).expanduser().resolve()
                backup_snapshot = backend.snapshot(backup_path)
                expected_prior_hash = rollback_plan.get("prior_output_sha256")
                if not backup_snapshot.get("is_dir") or not _hashes_equal(
                    backup_snapshot.get("sha256"), expected_prior_hash
                ):
                    raise RuntimeError(
                        "unpack rollback backup is missing or does not match its planned hash"
                    )
                backend.replace_tree(backup_path, output_path)
                restored_snapshot = backend.snapshot(output_path)
                restored = _hashes_equal(
                    restored_snapshot.get("sha256"), expected_prior_hash
                )
                details.update(
                    {
                        "backup_path": str(backup_path),
                        "prior_output_sha256": expected_prior_hash,
                        "restored_sha256": restored_snapshot.get("sha256"),
                    }
                )
            else:
                raise RuntimeError(f"unsupported Android rebuild rollback mode: {mode}")
            details["status"] = "ok" if restored else "failed"
            if not restored:
                details["error"] = "rollback did not restore the prior output state"
        except Exception as exc:
            details["error"] = str(exc) or exc.__class__.__name__

        self._record_rollback(result, details, backend=backend)
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=restored,
            restored=restored,
            details=_prune(details),
        )

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        del context
        artifacts = list(result.artifacts or [])
        collection_root = str(Path(out_dir).expanduser().resolve())
        for artifact in artifacts:
            artifact.metadata.setdefault("collection_root", collection_root)
        entries_by_path = {
            str(entry.get("path")): dict(entry)
            for entry in result.evidence_manifest_entries or []
            if entry.get("path")
        }
        manifest_entries: list[dict[str, Any]] = []
        collected_paths: set[str] = set()
        for artifact in artifacts:
            manifest_entries.append(
                entries_by_path.get(
                    artifact.path,
                    _manifest_entry(
                        artifact,
                        status=result.status,
                        strategy=str(
                            result.provenance.get("strategy") or result.action
                        ),
                    ),
                )
            )
            collected_paths.add(artifact.path)
        for entry in result.evidence_manifest_entries or []:
            entry_path = str(entry.get("path") or "")
            if entry_path and entry_path not in collected_paths:
                manifest_entries.append(dict(entry))
                collected_paths.add(entry_path)
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=manifest_entries,
        )

    def _execute_verify(
        self,
        plan: CapabilityPlan,
        *,
        context: Optional[dict[str, Any]],
    ) -> CapabilityExecutionResult:
        backend = self._select_backend(context)
        runner = self._select_runner(context)
        validation = self.validate(plan, context=context)
        source_path = _plan_path(plan, "source_path", plan.target.path)
        source_before = backend.inspect_apk(source_path)
        before_snapshot = {
            **_json_mapping(plan.before_snapshot),
            "execution_source": source_before,
            "validation": validation.to_dict(),
        }
        command_records: list[dict[str, Any]] = []
        signing = _static_signature_result(source_before)
        unavailable = next(
            (
                item
                for item in validation.checks
                if item.get("name") == "apksigner_available"
                and item.get("status") == "unavailable"
            ),
            None,
        )
        if unavailable is not None:
            reason = str(unavailable.get("reason") or "apksigner is unavailable")
            return self._action_execution_result(
                plan,
                validation=validation,
                status="unavailable",
                before_snapshot=before_snapshot,
                after_snapshot={"source": backend.inspect_apk(source_path), "side_effects": False},
                rollback_plan=_non_execution_rollback_plan(reason),
                command_records=command_records,
                signing={"status": "unavailable", "reason": reason},
                error=reason,
                backend=backend,
            )
        if not validation.ok:
            reason = "; ".join(validation.errors) or "Android APK verification failed"
            return self._action_execution_result(
                plan,
                validation=validation,
                status="failed",
                before_snapshot=before_snapshot,
                after_snapshot={"source": backend.inspect_apk(source_path), "side_effects": False},
                rollback_plan=_non_execution_rollback_plan(reason),
                command_records=command_records,
                signing=signing,
                error=reason,
                backend=backend,
            )

        try:
            if _coerce_bool(plan.parameters.get("verify_signature"), default=False):
                tool = _resolve_named_tools(plan, runner, ("apksigner",))["apksigner"]
                backend.ensure_dir(_plan_path(plan, "artifact_dir"))
                command = [
                    tool["path"],
                    "verify",
                    "--verbose",
                    "--print-certs",
                    str(source_path),
                ]
                record = _run_recorded(
                    command_records,
                    runner,
                    command,
                    cwd=_plan_path(plan, "artifact_dir"),
                    timeout=_bounded_timeout(
                        plan.parameters.get("timeout"), self.timeout
                    ),
                    step="apksigner_verify",
                )
                signing = {
                    "status": "ok",
                    "mode": "apksigner",
                    "verified": True,
                    "verification_stdout": record.get("stdout"),
                }
            source_after = backend.inspect_apk(source_path)
            if not _hashes_equal(source_after.get("sha256"), plan.precondition_hash):
                raise RuntimeError("source APK changed during verification")
            return self._action_execution_result(
                plan,
                validation=validation,
                status="ok",
                before_snapshot=before_snapshot,
                after_snapshot={
                    "source": source_after,
                    "sha256": source_after.get("sha256"),
                    "zip_integrity": source_after.get("zip_integrity"),
                    "manifest_present": source_after.get("manifest_present"),
                    "side_effects": False,
                },
                rollback_plan=_non_execution_rollback_plan(
                    "verify does not modify the target APK"
                ),
                command_records=command_records,
                signing=signing,
                error=None,
                backend=backend,
            )
        except Exception as exc:
            reason = str(exc) or exc.__class__.__name__
            return self._action_execution_result(
                plan,
                validation=validation,
                status="failed",
                before_snapshot=before_snapshot,
                after_snapshot={"source": backend.inspect_apk(source_path), "side_effects": False},
                rollback_plan=_non_execution_rollback_plan(reason),
                command_records=command_records,
                signing={"status": "failed", "reason": reason},
                error=reason,
                backend=backend,
            )

    def _execute_unpack(
        self,
        plan: CapabilityPlan,
        *,
        context: Optional[dict[str, Any]],
    ) -> CapabilityExecutionResult:
        backend = self._select_backend(context)
        runner = self._select_runner(context)
        validation = self.validate(plan, context=context)
        strategy = _normalize_strategy(plan.parameters.get("strategy"))
        source_path = _plan_path(plan, "source_path", plan.target.path)
        unpack_dir = _plan_path(plan, "unpack_dir")
        temporary_unpack = _plan_path(plan, "temporary_unpack")
        before_snapshot = {
            **_json_mapping(plan.before_snapshot),
            "execution_source": backend.snapshot(source_path),
            "execution_unpack": backend.snapshot(unpack_dir),
            "validation": validation.to_dict(),
        }
        command_records: list[dict[str, Any]] = []
        unavailable = next(
            (
                item
                for item in validation.checks
                if item.get("name") == "apktool_available"
                and item.get("status") == "unavailable"
            ),
            None,
        )
        if unavailable is not None:
            reason = str(unavailable.get("reason") or "apktool is unavailable")
            return self._action_execution_result(
                plan,
                validation=validation,
                status="unavailable",
                before_snapshot=before_snapshot,
                after_snapshot={
                    "source": backend.snapshot(source_path),
                    "unpack": backend.snapshot(unpack_dir),
                    "side_effects": False,
                },
                rollback_plan=_non_execution_rollback_plan(reason),
                command_records=command_records,
                signing={"status": "not_applicable"},
                error=reason,
                backend=backend,
            )
        if not validation.ok:
            reason = "; ".join(validation.errors) or "Android APK unpack validation failed"
            return self._action_execution_result(
                plan,
                validation=validation,
                status="failed",
                before_snapshot=before_snapshot,
                after_snapshot={
                    "source": backend.snapshot(source_path),
                    "unpack": backend.snapshot(unpack_dir),
                    "side_effects": False,
                },
                rollback_plan=_non_execution_rollback_plan(reason),
                command_records=command_records,
                signing={"status": "not_applicable"},
                error=reason,
                backend=backend,
            )

        current_output: dict[str, Any] = {}
        backup_path = _plan_path(plan, "backup_path")
        try:
            backend.ensure_dir(temporary_unpack.parent)
            if strategy == _ZIP_COPY:
                backend.extract_apk(source_path, temporary_unpack)
            else:
                tool = _resolve_named_tools(plan, runner, ("apktool",))["apktool"]
                _run_recorded(
                    command_records,
                    runner,
                    [
                        tool["path"],
                        "d",
                        "-f",
                        str(source_path),
                        "-o",
                        str(temporary_unpack),
                        "--frame-path",
                        str(_plan_path(plan, "work_dir") / "framework"),
                    ],
                    cwd=_plan_path(plan, "work_dir"),
                    timeout=_bounded_timeout(plan.parameters.get("timeout"), self.timeout),
                    step="apktool_decode",
                )
            temporary_snapshot = backend.snapshot(temporary_unpack)
            temporary_manifest = backend.snapshot(temporary_unpack / "AndroidManifest.xml")
            if not temporary_snapshot.get("is_dir") or not temporary_manifest.get("is_file"):
                raise RuntimeError("unpacked APK is missing root AndroidManifest.xml")
            if int(temporary_manifest.get("size") or 0) <= 0:
                raise RuntimeError("unpacked AndroidManifest.xml is empty")
            current_source = backend.snapshot(source_path)
            if not _hashes_equal(current_source.get("sha256"), plan.precondition_hash):
                raise RuntimeError("source APK changed during unpack execution")
            current_output = backend.snapshot(unpack_dir)
            if not _same_snapshot(plan.before_snapshot.get("unpack"), current_output):
                raise RuntimeError("unpack destination changed during execution")
            if current_output.get("exists"):
                backend.ensure_dir(backup_path.parent)
                backend.copy_tree(unpack_dir, backup_path)
            try:
                backend.replace_tree(temporary_unpack, unpack_dir)
            except Exception:
                self._restore_failed_unpack_commit(
                    backend,
                    unpack_dir=unpack_dir,
                    backup_path=backup_path,
                    output_existed=bool(current_output.get("exists")),
                )
                raise
            unpack_snapshot = backend.snapshot(unpack_dir)
            manifest_snapshot = backend.snapshot(unpack_dir / "AndroidManifest.xml")
            if not unpack_snapshot.get("is_dir") or not manifest_snapshot.get("is_file"):
                self._restore_failed_unpack_commit(
                    backend,
                    unpack_dir=unpack_dir,
                    backup_path=backup_path,
                    output_existed=bool(current_output.get("exists")),
                )
                raise RuntimeError("committed unpack directory failed manifest verification")
            rollback_plan = {
                **dict(plan.rollback_plan or {}),
                "supported": True,
                "mode": "restore_unpack"
                if current_output.get("exists")
                else "delete_unpack",
                "output_path": str(unpack_dir),
                "output_existed": bool(current_output.get("exists")),
                "prior_output_sha256": current_output.get("sha256"),
                "backup_path": str(backup_path)
                if current_output.get("exists")
                else None,
                "output_sha256": unpack_snapshot.get("sha256"),
                "completed": False,
            }
            return self._action_execution_result(
                plan,
                validation=validation,
                status="ok",
                before_snapshot=before_snapshot,
                after_snapshot={
                    "source": current_source,
                    "unpack": unpack_snapshot,
                    "manifest": manifest_snapshot,
                    "sha256": unpack_snapshot.get("sha256"),
                    "side_effects": True,
                },
                rollback_plan=_prune(rollback_plan),
                command_records=command_records,
                signing={"status": "not_applicable"},
                error=None,
                backend=backend,
            )
        except Exception as exc:
            backend.remove_tree(temporary_unpack)
            failed_record = getattr(exc, "command_record", None)
            if failed_record and failed_record not in command_records:
                command_records.append(failed_record)
            reason = str(exc) or exc.__class__.__name__
            return self._action_execution_result(
                plan,
                validation=validation,
                status="failed",
                before_snapshot=before_snapshot,
                after_snapshot={
                    "source": backend.snapshot(source_path),
                    "unpack": backend.snapshot(unpack_dir),
                    "side_effects": False,
                },
                rollback_plan=_non_execution_rollback_plan(reason),
                command_records=command_records,
                signing={"status": "not_applicable"},
                error=reason,
                backend=backend,
            )
        finally:
            backend.remove_tree(temporary_unpack)
            if not bool(plan.parameters.get("keep_work_dir")) and not bool(
                plan.parameters.get("work_dir_existed")
            ):
                backend.remove_tree(_plan_path(plan, "work_dir"))

    def _action_execution_result(
        self,
        plan: CapabilityPlan,
        *,
        validation: CapabilityValidation,
        status: str,
        before_snapshot: Mapping[str, Any],
        after_snapshot: Mapping[str, Any],
        rollback_plan: Mapping[str, Any],
        command_records: list[dict[str, Any]],
        signing: Mapping[str, Any],
        error: Optional[str],
        backend: AndroidRebuildBackend,
    ) -> CapabilityExecutionResult:
        action = _normalize_action(plan.action)
        strategy = str(plan.parameters.get("strategy") or "")
        capability_boundary = _plan_capability_boundary(
            plan,
            checks=validation.checks,
        )
        source_path = _plan_path(plan, "source_path", plan.target.path)
        source = backend.inspect_apk(source_path)
        destination_path = (
            _plan_path(plan, "unpack_dir") if action == "unpack" else source_path
        )
        destination = (
            backend.snapshot(destination_path) if action == "unpack" else source
        )
        checks = [
            {
                "name": "source_sha256_unchanged",
                "status": "ok"
                if _hashes_equal(source.get("sha256"), plan.precondition_hash)
                else "failed",
                "expected": plan.precondition_hash,
                "actual": source.get("sha256"),
            },
            {
                "name": "source_zip_integrity",
                "status": "ok" if source.get("zip_integrity") else "failed",
                "bad_member": source.get("bad_member"),
            },
            {
                "name": "source_manifest",
                "status": "ok" if source.get("manifest_present") else "failed",
                "size": source.get("manifest_size"),
            },
        ]
        if action == "unpack":
            manifest = backend.snapshot(destination_path / "AndroidManifest.xml")
            checks.extend(
                [
                    {
                        "name": "unpack_directory",
                        "status": "ok"
                        if status == "ok" and destination.get("is_dir")
                        else ("not_run" if status == "unavailable" else "failed"),
                        "entry_count": destination.get("entry_count"),
                    },
                    {
                        "name": "unpacked_manifest",
                        "status": "ok"
                        if status == "ok" and manifest.get("is_file")
                        else ("not_run" if status == "unavailable" else "failed"),
                        "size": manifest.get("size"),
                    },
                ]
            )
        else:
            checks.append(
                {
                    "name": "signing_integrity",
                    **_json_mapping(signing),
                }
            )
        verification_payload = _with_capability_boundary(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "kind": f"android_{action}_verify",
                "status": status,
                "action": action,
                "provider": plan.provider,
                "session_id": plan.session_id,
                "strategy": strategy,
                "source": source,
                "destination": destination if action == "unpack" else None,
                "checks": checks,
                "signing": signing if action == "verify" else None,
                "commands": command_records,
                "error": error,
            },
            capability_boundary,
        )
        verify_path = _plan_path(plan, "verify_path")
        audit_path = _plan_path(plan, "audit_path")
        artifact_errors: list[str] = []
        artifacts: list[CapabilityArtifact] = []
        if action == "unpack" and status == "ok" and destination.get("is_dir"):
            artifacts.append(
                CapabilityArtifact(
                    path=str(destination_path),
                    kind="android-unpacked-directory",
                    description=f"Verified Android APK unpacked by {strategy}",
                    metadata={
                        "materialized": True,
                        "role": "unpacked-directory",
                        "sha256": destination.get("sha256"),
                        "entry_count": destination.get("entry_count"),
                        "strategy": strategy,
                    },
                )
            )
        try:
            backend.write_json(verify_path, verification_payload)
            artifacts.append(
                CapabilityArtifact(
                    path=str(verify_path),
                    kind=f"android-{action}-verify",
                    description=f"Android APK {action} verification record",
                    metadata={
                        "materialized": True,
                        "role": f"{action}-verification",
                        "sha256": backend.snapshot(verify_path).get("sha256"),
                    },
                )
            )
        except Exception as exc:
            artifact_errors.append(f"could not write {action} verification: {exc}")
        result_status = "partial" if status == "ok" and artifact_errors else status
        provenance = _with_capability_boundary(
            {
                **_json_mapping(plan.provenance),
                "action": action,
                "strategy": strategy,
                "precondition_hash": plan.precondition_hash,
                "source_sha256": source.get("sha256"),
                "destination_path": str(destination_path) if action == "unpack" else None,
                "destination_sha256": destination.get("sha256")
                if action == "unpack" and status == "ok"
                else None,
                "verify_artifact": str(verify_path),
                "command_steps": [item.get("step") for item in command_records],
                "signing": signing if action == "verify" else None,
                "audit_complete": not artifact_errors,
            },
            capability_boundary,
        )
        audit_payload = _with_capability_boundary(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "kind": f"android_{action}_audit",
                "status": result_status,
                "operation_status": status,
                "capability": plan.capability,
                "action": action,
                "provider": plan.provider,
                "session_id": plan.session_id,
                "plan": plan.to_dict(),
                "validation": validation.to_dict(),
                "before_snapshot": before_snapshot,
                "after_snapshot": after_snapshot,
                "rollback_plan": rollback_plan,
                "verification": verification_payload,
                "provenance": provenance,
                "artifact_errors": artifact_errors,
            },
            capability_boundary,
        )
        try:
            backend.write_json(audit_path, audit_payload)
            artifacts.append(
                CapabilityArtifact(
                    path=str(audit_path),
                    kind=f"android-{action}-audit",
                    description=f"Transactional Android {action} audit record",
                    metadata={
                        "materialized": True,
                        "role": f"{action}-audit",
                        "sha256": backend.snapshot(audit_path).get("sha256"),
                    },
                )
            )
        except Exception as exc:
            artifact_errors.append(f"could not write {action} audit: {exc}")
        result_status = "partial" if status == "ok" and artifact_errors else status
        provenance["audit_complete"] = not artifact_errors
        if artifact_errors:
            provenance["artifact_errors"] = list(artifact_errors)
        manifest_entries = [
            _manifest_entry(artifact, status=result_status, strategy=strategy)
            for artifact in artifacts
        ]
        if not manifest_entries:
            manifest_entries.append(
                _input_evidence_entry(
                    source_path,
                    source,
                    status=result_status,
                    strategy=strategy,
                )
            )
        report_section = _with_capability_boundary(
            {
                "status": result_status,
                "operation_status": status,
                "capability": plan.capability,
                "provider": plan.provider,
                "action": action,
                "target_format": "apk",
                "strategy": strategy,
                "source_path": str(source_path),
                "destination_path": str(destination_path) if action == "unpack" else None,
                "source_sha256": source.get("sha256"),
                "destination_sha256": destination.get("sha256")
                if action == "unpack" and status == "ok"
                else None,
                "zip_integrity": source.get("zip_integrity"),
                "manifest_present": source.get("manifest_present"),
                "signing": signing if action == "verify" else None,
                "verify_artifact": str(verify_path),
                "audit_artifact": str(audit_path),
                "validation": validation.to_dict(),
                "error": error,
                "artifact_errors": artifact_errors,
            },
            capability_boundary,
        )
        dashboard_trace = [
            _with_capability_boundary(
                {
                    "kind": f"android_{action}_execution",
                    "capability": plan.capability,
                    "provider": plan.provider,
                    "action": action,
                    "strategy": strategy,
                    "status": result_status,
                    "operation_status": status,
                    "source_path": str(source_path),
                    "destination_path": str(destination_path)
                    if action == "unpack"
                    else None,
                    "source_sha256": source.get("sha256"),
                },
                capability_boundary,
            )
        ]
        return CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status=result_status,
            action=action,
            target=plan.target,
            before_snapshot=dict(before_snapshot),
            after_snapshot=dict(after_snapshot),
            rollback_plan=dict(rollback_plan),
            artifacts=artifacts,
            evidence_manifest_entries=manifest_entries,
            report_section=report_section,
            dashboard_trace=dashboard_trace,
            provenance=provenance,
        )

    def _execute_apktool_rebuild(
        self,
        plan: CapabilityPlan,
        *,
        runner: Any,
        backend: AndroidRebuildBackend,
        source_path: Path,
        temporary_output: Path,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        tools = _resolve_toolchain(plan, runner)
        if not all(item["available"] for item in tools.values()):
            raise RuntimeError("apktool and apksigner are required for apktool_rebuild")
        work_dir = _plan_path(plan, "work_dir")
        decoded_dir = _plan_path(plan, "decoded_dir")
        unsigned_path = _plan_path(plan, "unsigned_path")
        backend.ensure_dir(work_dir)
        records: list[dict[str, Any]] = []
        timeout = _bounded_timeout(plan.parameters.get("timeout"), self.timeout)
        project_dir = plan.parameters.get("project_dir")
        if not project_dir:
            decode_command = [
                tools["apktool"]["path"],
                "d",
                "-f",
                str(source_path),
                "-o",
                str(decoded_dir),
                "--frame-path",
                str(work_dir / "framework"),
            ]
            _run_recorded(
                records,
                runner,
                decode_command,
                cwd=work_dir,
                timeout=timeout,
                step="apktool_decode",
            )
        build_command = [
            tools["apktool"]["path"],
            "b",
            str(decoded_dir),
            "-o",
            str(unsigned_path),
            "--frame-path",
            str(work_dir / "framework"),
        ]
        _run_recorded(
            records,
            runner,
            build_command,
            cwd=work_dir,
            timeout=timeout,
            step="apktool_rebuild",
        )
        if not backend.snapshot(unsigned_path).get("is_file"):
            raise RuntimeError("apktool reported success without producing an unsigned APK")

        private_signing = dict(self._signing_secrets.get(plan.session_id) or {})
        sign_command = _apksigner_sign_command(
            tools["apksigner"]["path"],
            unsigned_path=unsigned_path,
            output_path=temporary_output,
            public=_json_mapping(plan.parameters.get("signing")),
            private=private_signing,
        )
        _run_recorded(
            records,
            runner,
            sign_command,
            cwd=work_dir,
            timeout=timeout,
            step="apksigner_sign",
        )
        if not backend.snapshot(temporary_output).get("is_file"):
            raise RuntimeError("apksigner reported success without producing a signed APK")
        verify_command = [
            tools["apksigner"]["path"],
            "verify",
            "--verbose",
            "--print-certs",
            str(temporary_output),
        ]
        verify_record = _run_recorded(
            records,
            runner,
            verify_command,
            cwd=work_dir,
            timeout=timeout,
            step="apksigner_verify",
        )
        return records, {
            "status": "ok",
            "mode": "apksigner",
            "verified": True,
            "verification_stdout": verify_record.get("stdout"),
        }

    def _execution_result(
        self,
        plan: CapabilityPlan,
        *,
        validation: CapabilityValidation,
        status: str,
        before_snapshot: Mapping[str, Any],
        after_snapshot: Mapping[str, Any],
        rollback_plan: Mapping[str, Any],
        command_records: list[dict[str, Any]],
        signing: Mapping[str, Any],
        error: Optional[str],
        backend: AndroidRebuildBackend,
    ) -> CapabilityExecutionResult:
        strategy = str(plan.parameters.get("strategy") or "")
        capability_boundary = _plan_capability_boundary(
            plan,
            checks=validation.checks,
        )
        source_path = _plan_path(plan, "source_path", plan.target.path)
        output_path = _plan_path(plan, "out_path")
        source_snapshot = backend.snapshot(source_path)
        output_snapshot = backend.inspect_apk(output_path)
        verification_checks = [
            {
                "name": "source_sha256_unchanged",
                "status": "ok"
                if _hashes_equal(source_snapshot.get("sha256"), plan.precondition_hash)
                else "failed",
                "expected": plan.precondition_hash,
                "actual": source_snapshot.get("sha256"),
            },
            {
                "name": "output_zip_integrity",
                "status": "ok"
                if status == "ok" and output_snapshot.get("zip_integrity")
                else ("not_run" if status == "unavailable" else "failed"),
                "bad_member": output_snapshot.get("bad_member"),
            },
            {
                "name": "output_manifest",
                "status": "ok"
                if status == "ok" and output_snapshot.get("manifest_present")
                else ("not_run" if status == "unavailable" else "failed"),
                "size": output_snapshot.get("manifest_size"),
            },
            {
                "name": "signing_integrity",
                "status": signing.get("status", "unknown"),
                **_json_mapping(signing),
            },
        ]
        if strategy == _ZIP_COPY and status == "ok":
            verification_checks.append(
                {
                    "name": "byte_preserving_hash",
                    "status": "ok"
                    if _hashes_equal(
                        source_snapshot.get("sha256"), output_snapshot.get("sha256")
                    )
                    else "failed",
                    "source_sha256": source_snapshot.get("sha256"),
                    "output_sha256": output_snapshot.get("sha256"),
                }
            )
        rebuild_verify = _with_capability_boundary(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "kind": "android_rebuild_verify",
                "status": status,
                "provider": plan.provider,
                "session_id": plan.session_id,
                "strategy": strategy,
                "source": source_snapshot,
                "output": output_snapshot,
                "checks": verification_checks,
                "signing": signing,
                "commands": command_records,
                "error": error,
            },
            capability_boundary,
        )
        verify_path = _plan_path(plan, "verify_path")
        audit_path = _plan_path(plan, "audit_path")
        artifact_errors: list[str] = []
        artifacts: list[CapabilityArtifact] = []
        if status == "ok" and output_snapshot.get("is_file"):
            artifacts.append(
                CapabilityArtifact(
                    path=str(output_path),
                    kind="android-rebuilt-apk",
                    description=f"Verified Android APK produced by {strategy}",
                    metadata={
                        "materialized": True,
                        "role": "rebuilt-apk",
                        "sha256": output_snapshot.get("sha256"),
                        "size": output_snapshot.get("size"),
                        "strategy": strategy,
                    },
                )
            )
        try:
            backend.write_json(verify_path, rebuild_verify)
            verify_snapshot = backend.snapshot(verify_path)
            artifacts.append(
                CapabilityArtifact(
                    path=str(verify_path),
                    kind="android-rebuild-verify",
                    description="APK rebuild ZIP, manifest, hash, and signing verification",
                    metadata={
                        "materialized": True,
                        "role": "rebuild-verification",
                        "sha256": verify_snapshot.get("sha256"),
                    },
                )
            )
        except Exception as exc:
            artifact_errors.append(f"could not write rebuild verification: {exc}")

        result_status = "partial" if status == "ok" and artifact_errors else status

        provenance = _with_capability_boundary(
            {
                **_json_mapping(plan.provenance),
                "strategy": strategy,
                "precondition_hash": plan.precondition_hash,
                "source_sha256": source_snapshot.get("sha256"),
                "output_sha256": output_snapshot.get("sha256") if status == "ok" else None,
                "rebuild_verify": str(verify_path),
                "command_steps": [item.get("step") for item in command_records],
                "signing": signing,
                "audit_complete": not artifact_errors,
            },
            capability_boundary,
        )
        audit_payload = _with_capability_boundary(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "kind": "android_rebuild_audit",
                "status": result_status,
                "operation_status": status,
                "capability": plan.capability,
                "provider": plan.provider,
                "session_id": plan.session_id,
                "plan": plan.to_dict(),
                "validation": validation.to_dict(),
                "before_snapshot": before_snapshot,
                "after_snapshot": after_snapshot,
                "rollback_plan": rollback_plan,
                "rebuild_verify": rebuild_verify,
                "provenance": provenance,
                "artifact_errors": artifact_errors,
            },
            capability_boundary,
        )
        try:
            backend.write_json(audit_path, audit_payload)
            audit_snapshot = backend.snapshot(audit_path)
            artifacts.append(
                CapabilityArtifact(
                    path=str(audit_path),
                    kind="android-rebuild-audit",
                    description="Transactional Android rebuild audit record",
                    metadata={
                        "materialized": True,
                        "role": "rebuild-audit",
                        "sha256": audit_snapshot.get("sha256"),
                    },
                )
            )
        except Exception as exc:
            artifact_errors.append(f"could not write rebuild audit: {exc}")

        result_status = "partial" if status == "ok" and artifact_errors else status
        provenance["audit_complete"] = not artifact_errors
        if artifact_errors:
            provenance["artifact_errors"] = list(artifact_errors)

        manifest_entries = [
            _manifest_entry(artifact, status=result_status, strategy=strategy)
            for artifact in artifacts
        ]
        if not manifest_entries:
            manifest_entries.append(
                _input_evidence_entry(
                    source_path,
                    source_snapshot,
                    status=result_status,
                    strategy=strategy,
                )
            )
        report_section = _with_capability_boundary(
            {
                "status": result_status,
                "operation_status": status,
                "capability": plan.capability,
                "provider": plan.provider,
                "action": plan.action,
                "target_format": "apk",
                "strategy": strategy,
                "source_path": str(source_path),
                "output_path": str(output_path) if status == "ok" else None,
                "source_sha256": source_snapshot.get("sha256"),
                "output_sha256": output_snapshot.get("sha256") if status == "ok" else None,
                "zip_integrity": output_snapshot.get("zip_integrity") if status == "ok" else None,
                "manifest_present": output_snapshot.get("manifest_present") if status == "ok" else None,
                "signing": signing,
                "rebuild_verify": str(verify_path),
                "audit_artifact": str(audit_path),
                "validation": validation.to_dict(),
                "error": error,
                "artifact_errors": artifact_errors,
            },
            capability_boundary,
        )
        dashboard_trace = [
            _with_capability_boundary(
                {
                    "kind": "android_rebuild_execution",
                    "capability": plan.capability,
                    "provider": plan.provider,
                    "strategy": strategy,
                    "status": result_status,
                    "operation_status": status,
                    "source_path": str(source_path),
                    "output_path": str(output_path) if status == "ok" else None,
                    "source_sha256": source_snapshot.get("sha256"),
                    "output_sha256": output_snapshot.get("sha256") if status == "ok" else None,
                },
                capability_boundary,
            )
        ]
        return CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status=result_status,
            action=plan.action,
            target=plan.target,
            before_snapshot=dict(before_snapshot),
            after_snapshot=dict(after_snapshot),
            rollback_plan=dict(rollback_plan),
            artifacts=artifacts,
            evidence_manifest_entries=manifest_entries,
            report_section=report_section,
            dashboard_trace=dashboard_trace,
            provenance=provenance,
        )

    def _record_rollback(
        self,
        result: CapabilityExecutionResult,
        details: Mapping[str, Any],
        *,
        backend: AndroidRebuildBackend,
    ) -> None:
        ok = details.get("status") == "ok"
        result.rollback_plan.update(
            {
                "completed": ok,
                "rollback_status": details.get("status"),
                "rollback_details": _json_mapping(details),
            }
        )
        result.after_snapshot["rollback"] = _json_mapping(details)
        result.report_section["rollback"] = _json_mapping(details)
        result.provenance["rollback"] = _json_mapping(details)
        result.dashboard_trace.append(
            _prune(
                {
                    "kind": "android_rebuild_rollback",
                    "capability": result.capability,
                    "provider": result.provider,
                    "status": details.get("status"),
                    "mode": details.get("mode"),
                    "output_path": details.get("output_path"),
                }
            )
        )
        read_only_entries = [
            dict(entry)
            for entry in result.evidence_manifest_entries or []
            if entry.get("read_only")
        ]
        if ok:
            result.artifacts = [
                artifact
                for artifact in result.artifacts
                if artifact.kind
                not in {"android-rebuilt-apk", "android-unpacked-directory"}
            ]
        for artifact in result.artifacts:
            path = Path(artifact.path)
            if (
                artifact.kind.startswith("android-")
                and artifact.kind.endswith(("-verify", "-audit"))
            ):
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    payload["rollback"] = _json_mapping(details)
                    backend.write_json(path, payload)
                except (OSError, ValueError, TypeError):
                    pass
            current_snapshot = backend.snapshot(path)
            if current_snapshot.get("sha256"):
                artifact.metadata["sha256"] = current_snapshot["sha256"]
        strategy = str(result.provenance.get("strategy") or result.action)
        result.evidence_manifest_entries = [
            _manifest_entry(artifact, status=result.status, strategy=strategy)
            for artifact in result.artifacts
        ]
        materialized_paths = {
            str(entry.get("path")) for entry in result.evidence_manifest_entries
        }
        result.evidence_manifest_entries.extend(
            entry
            for entry in read_only_entries
            if str(entry.get("path")) not in materialized_paths
        )
        if not result.evidence_manifest_entries and result.target.path:
            source_path = Path(result.target.path).expanduser().resolve()
            result.evidence_manifest_entries.append(
                _input_evidence_entry(
                    source_path,
                    backend.snapshot(source_path),
                    status=result.status,
                    strategy=strategy,
                )
            )

    @staticmethod
    def _restore_failed_commit(
        backend: AndroidRebuildBackend,
        *,
        output_path: Path,
        backup_path: Path,
        output_existed: bool,
    ) -> None:
        if output_existed and backend.snapshot(backup_path).get("is_file"):
            backend.replace_file(backup_path, output_path)
        elif not output_existed:
            backend.remove_file(output_path)

    @staticmethod
    def _restore_failed_unpack_commit(
        backend: AndroidRebuildBackend,
        *,
        unpack_dir: Path,
        backup_path: Path,
        output_existed: bool,
    ) -> None:
        backend.remove_tree(unpack_dir)
        if output_existed and backend.snapshot(backup_path).get("is_dir"):
            backend.replace_tree(backup_path, unpack_dir)

    def _select_backend(
        self, context: Optional[dict[str, Any]]
    ) -> AndroidRebuildBackend:
        if context:
            candidate = context.get("android_rebuild_backend") or context.get("backend")
            if candidate is not None:
                return candidate
        return self.backend

    def _select_runner(self, context: Optional[dict[str, Any]]) -> Any:
        if context:
            candidate = context.get("android_rebuild_runner") or context.get("runner")
            if candidate is not None:
                return candidate
        return self.runner


class AndroidRebuildMockProvider(MockCapabilityProvider):
    def __init__(self) -> None:
        super().__init__("android_rebuild")


def _request_source_path(request: CapabilityRequest) -> Path:
    if not request.target.path:
        raise ValueError("android_rebuild requires an APK file or decoded project target")
    return Path(request.target.path).expanduser().resolve()


def _normalize_action(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _request_strategy(
    request: CapabilityRequest,
    default: str,
    *,
    source_is_project: bool = False,
) -> str:
    requested = request.params.get("strategy")
    if requested in (None, ""):
        action_strategy = _normalize_strategy(request.action)
        if action_strategy in _SUPPORTED_STRATEGIES:
            requested = action_strategy
        elif source_is_project:
            requested = _APKTOOL_REBUILD
        else:
            requested = default
    return _normalize_strategy(requested)


def _normalize_strategy(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")
    aliases = {
        "copy": _ZIP_COPY,
        "python_copy": _ZIP_COPY,
        "python_zip_copy": _ZIP_COPY,
        "apktool": _APKTOOL_REBUILD,
        "apktool_apksigner": _APKTOOL_REBUILD,
        "apktool_rebuild_apksigner": _APKTOOL_REBUILD,
    }
    return aliases.get(normalized, normalized)


def _request_output_path(
    request: CapabilityRequest,
    source_path: Path,
    *,
    context: Optional[dict[str, Any]],
) -> Path:
    value = _first_value(request.params, ("out_path", "output_path"))
    if value not in (None, ""):
        return Path(str(value)).expanduser().resolve()
    if context and context.get("out_dir"):
        return (
            Path(str(context["out_dir"])).expanduser().resolve()
            / "android"
            / f"{source_path.stem}.rebuilt.apk"
        )
    return source_path.with_name(f"{source_path.stem}.rebuilt.apk")


def _request_unpack_dir(
    request: CapabilityRequest,
    source_path: Path,
    *,
    context: Optional[dict[str, Any]],
) -> Path:
    value = request.params.get("unpack_dir")
    if value not in (None, ""):
        return Path(str(value)).expanduser().resolve()
    if context and context.get("out_dir"):
        return (
            Path(str(context["out_dir"])).expanduser().resolve()
            / "android"
            / f"{source_path.stem}.unpacked"
        )
    return source_path.with_name(f"{source_path.stem}.unpacked")


def _request_artifact_dir(
    request: CapabilityRequest,
    output_path: Path,
    *,
    context: Optional[dict[str, Any]],
) -> Path:
    value = request.params.get("artifact_dir")
    if value not in (None, ""):
        return Path(str(value)).expanduser().resolve()
    if context and context.get("out_dir"):
        return Path(str(context["out_dir"])).expanduser().resolve() / "android"
    return output_path.parent / "android"


def _request_path(
    params: Mapping[str, Any],
    names: Sequence[str],
    *,
    default: Path,
) -> Path:
    value = _first_value(params, names)
    return Path(str(value)).expanduser().resolve() if value not in (None, "") else default.resolve()


def _first_value(mapping: Mapping[str, Any], names: Sequence[str]) -> Any:
    for name in names:
        value = mapping.get(name)
        if value not in (None, ""):
            return value
    return None


def _signing_configuration(
    params: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    keystore = _first_value(params, ("keystore", "keystore_path", "ks"))
    key_path = _first_value(params, ("key", "key_path", "private_key"))
    cert_path = _first_value(params, ("cert", "cert_path", "certificate"))
    alias = _first_value(params, ("key_alias", "ks_key_alias", "alias"))
    ks_pass = _first_value(params, ("ks_pass", "keystore_password"))
    key_pass = _first_value(params, ("key_pass", "key_password"))
    extra_value = params.get("apksigner_args") or []
    argument_errors = _apksigner_argument_errors(extra_value)
    if isinstance(extra_value, str):
        extra_args = [extra_value]
    elif isinstance(extra_value, (list, tuple)):
        extra_args = [str(item) for item in extra_value]
    else:
        extra_args = []
    mode = "keystore" if keystore else ("key_cert" if key_path or cert_path else "arguments")
    public = _prune(
        {
            "mode": mode,
            "keystore": str(Path(str(keystore)).expanduser().resolve()) if keystore else None,
            "key_path": str(Path(str(key_path)).expanduser().resolve()) if key_path else None,
            "cert_path": str(Path(str(cert_path)).expanduser().resolve()) if cert_path else None,
            "key_alias": str(alias) if alias else None,
            "ks_pass_configured": ks_pass is not None,
            "key_pass_configured": key_pass is not None,
            "extra_arg_count": len(extra_args),
            "argument_errors": argument_errors,
        }
    )
    private = {
        "ks_pass": str(ks_pass) if ks_pass is not None else None,
        "key_pass": str(key_pass) if key_pass is not None else None,
        "extra_args": extra_args,
    }
    return private, public


def _signing_configuration_errors(value: Any) -> list[str]:
    signing = _json_mapping(value)
    mode = signing.get("mode")
    errors: list[str] = []
    errors.extend(str(item) for item in signing.get("argument_errors") or [])
    if mode == "keystore":
        path = Path(str(signing.get("keystore") or "")).expanduser()
        if not path.is_file():
            errors.append("apksigner keystore does not exist")
    elif mode == "key_cert":
        key_path = Path(str(signing.get("key_path") or "")).expanduser()
        cert_path = Path(str(signing.get("cert_path") or "")).expanduser()
        if not key_path.is_file() or not cert_path.is_file():
            errors.append("apksigner key and certificate files are both required")
    elif int(signing.get("extra_arg_count") or 0) <= 0:
        errors.append("apktool_rebuild requires apksigner credentials or arguments")
    errors.extend(_apksigner_argument_errors(signing.get("extra_args")))
    return errors


def _apksigner_argument_errors(value: Any) -> list[str]:
    """Validate caller-supplied signer flags before composing the command.

    The provider owns the action, input and output arguments.  Allowing an
    extra ``--out``/positional APK would make audit records differ from the
    artifact that was validated, so those controls are rejected up front.
    Password flags remain supported for compatibility and are redacted in
    recorded commands.
    """
    if value in (None, ""):
        return []
    if isinstance(value, str):
        raw = [value]
    elif isinstance(value, (list, tuple)):
        raw = list(value)
    else:
        return ["apksigner extra arguments must be an array of option flags"]
    errors: list[str] = []
    managed = {
        "sign",
        "verify",
        "--out",
        "--ks",
        "--key",
        "--cert",
        "--ks-key-alias",
    }
    for index, item in enumerate(raw):
        token = str(item)
        if any(char in token for char in ("\x00", "\r", "\n")):
            errors.append(f"apksigner argument {index} contains control characters")
            continue
        option = token.split("=", 1)[0].casefold()
        if option in managed:
            errors.append(f"apksigner argument {token!r} is managed by the provider")
        elif not token.startswith("-"):
            errors.append("apksigner extra arguments must be option flags")
    return errors


def _apksigner_sign_command(
    command: str,
    *,
    unsigned_path: Path,
    output_path: Path,
    public: Mapping[str, Any],
    private: Mapping[str, Any],
) -> list[str]:
    result = [command, "sign", "--out", str(output_path)]
    mode = public.get("mode")
    if mode == "keystore":
        result.extend(["--ks", str(public.get("keystore"))])
        if public.get("key_alias"):
            result.extend(["--ks-key-alias", str(public["key_alias"])])
        if private.get("ks_pass") is not None:
            result.extend(["--ks-pass", _password_argument(private["ks_pass"])])
        if private.get("key_pass") is not None:
            result.extend(["--key-pass", _password_argument(private["key_pass"])])
    elif mode == "key_cert":
        result.extend(
            [
                "--key",
                str(public.get("key_path")),
                "--cert",
                str(public.get("cert_path")),
            ]
        )
        if private.get("key_pass") is not None:
            result.extend(["--key-pass", _password_argument(private["key_pass"])])
    result.extend(str(item) for item in private.get("extra_args") or [])
    result.append(str(unsigned_path))
    return result


def _password_argument(value: Any) -> str:
    text = str(value)
    if text.startswith(("pass:", "env:", "file:", "stdin")):
        return text
    return f"pass:{text}"


def _resolve_toolchain(
    plan: CapabilityPlan,
    runner: Any,
    *,
    probe: bool = False,
    cwd: Optional[Path] = None,
    timeout: float = 15.0,
) -> dict[str, dict[str, Any]]:
    return _resolve_named_tools(
        plan,
        runner,
        ("apktool", "apksigner"),
        probe=probe,
        cwd=cwd,
        timeout=timeout,
    )


def _resolve_named_tools(
    plan: CapabilityPlan,
    runner: Any,
    names: Sequence[str],
    *,
    probe: bool = False,
    cwd: Optional[Path] = None,
    timeout: float = 15.0,
) -> dict[str, dict[str, Any]]:
    configured = _json_mapping(plan.parameters.get("tools"))
    resolved = {
        name: _resolve_tool(runner, str(configured.get(name) or name), name=name)
        for name in names
    }
    if probe:
        probe_cwd = (cwd or Path.cwd()).expanduser().resolve()
        resolved = {
            name: _probe_tool(
                runner,
                details,
                name=name,
                cwd=probe_cwd,
                timeout=timeout,
            )
            for name, details in resolved.items()
        }
    return resolved


def _probe_tool(
    runner: Any,
    details: Mapping[str, Any],
    *,
    name: str,
    cwd: Path,
    timeout: float,
) -> dict[str, Any]:
    result = dict(details)
    if not result.get("available"):
        return result
    arguments = ["--version"] if name == "apktool" else ["version"]
    command = [str(result.get("path") or result.get("configured") or name), *arguments]
    try:
        normalized = _command_result(
            _invoke_runner(runner, command, cwd=cwd, timeout=max(1.0, timeout))
        )
    except Exception as exc:  # noqa: BLE001 - dependency diagnostics fail closed
        normalized = {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
        }
    output = str(normalized.get("stdout") or normalized.get("stderr") or "").strip()
    version = output.splitlines()[0][:512] if output else None
    runnable = normalized.get("ok") is True
    result.update(
        {
            "available": runnable,
            "runnable": runnable,
            "probe": {
                "command": _redact_command(command),
                "returncode": normalized.get("returncode"),
                "version": version,
            },
            "reason": (
                None
                if runnable
                else f"{name} version probe failed: {version or 'no diagnostic output'}"
            ),
        }
    )
    return result


def _resolve_tool(runner: Any, command: str, *, name: str) -> dict[str, Any]:
    candidate = Path(command).expanduser()
    if candidate.is_absolute() or candidate.parent != Path("."):
        available = candidate.is_file()
        return {
            "tool": name,
            "configured": command,
            "path": str(candidate.resolve()),
            "available": available,
            "reason": None if available else f"configured {name} executable does not exist",
        }
    resolver = getattr(runner, "which", None)
    if callable(resolver):
        try:
            resolved = resolver(command)
        except Exception as exc:
            return {
                "tool": name,
                "configured": command,
                "path": command,
                "available": False,
                "reason": str(exc),
            }
        return {
            "tool": name,
            "configured": command,
            "path": str(resolved or command),
            "available": bool(resolved),
            "reason": None if resolved else f"{name} was not found on PATH",
        }
    availability = getattr(runner, "is_available", None) or getattr(runner, "available", None)
    if callable(availability):
        try:
            available = bool(availability(command))
        except Exception as exc:
            available = False
            reason = str(exc)
        else:
            reason = None if available else f"{name} is unavailable"
        return {
            "tool": name,
            "configured": command,
            "path": command,
            "available": available,
            "reason": reason,
        }
    return {
        "tool": name,
        "configured": command,
        "path": command,
        "available": False,
        "reason": (
            f"{name} availability cannot be established because the injected "
            "runner exposes neither which() nor is_available()"
        ),
    }


def _run_checked(
    runner: Any,
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    step: str,
) -> dict[str, Any]:
    result = _invoke_runner(runner, command, cwd=cwd, timeout=timeout)
    normalized = _command_result(result)
    secrets = _command_secret_values(command)
    normalized["stdout"] = _redact_command_text(normalized.get("stdout"), secrets)
    normalized["stderr"] = _redact_command_text(normalized.get("stderr"), secrets)
    record = {
        "step": step,
        "command": _redact_command(command),
        **normalized,
    }
    if not normalized["ok"]:
        error = normalized.get("stderr") or normalized.get("stdout") or "command failed"
        exc = RuntimeError(f"{step} failed: {error}")
        setattr(exc, "command_record", record)
        raise exc
    return _prune(record)


def _run_recorded(
    records: list[dict[str, Any]],
    runner: Any,
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    step: str,
) -> dict[str, Any]:
    try:
        record = _run_checked(
            runner,
            command,
            cwd=cwd,
            timeout=timeout,
            step=step,
        )
    except Exception as exc:
        redacted_error = _redact_command_text(
            str(exc) or exc.__class__.__name__,
            _command_secret_values(command),
        )
        failed_record = getattr(exc, "command_record", None)
        if not failed_record:
            failed_record = {
                "step": step,
                "command": _redact_command(command),
                "ok": False,
                "error": redacted_error,
            }
        records.append(failed_record)
        if redacted_error != str(exc):
            redacted_exception = RuntimeError(redacted_error)
            setattr(redacted_exception, "command_record", failed_record)
            setattr(redacted_exception, "command_records", list(records))
            raise redacted_exception from exc
        setattr(exc, "command_record", failed_record)
        setattr(exc, "command_records", list(records))
        raise
    records.append(record)
    return record


def _invoke_runner(
    runner: Any,
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
) -> Any:
    callable_runner = getattr(runner, "run", None)
    if not callable(callable_runner) and callable(runner):
        callable_runner = runner
    if not callable(callable_runner):
        raise TypeError("Android rebuild runner must be callable or expose run()")
    arguments = [str(item) for item in command]
    try:
        return callable_runner(arguments, cwd=str(cwd), timeout=timeout)
    except TypeError:
        try:
            return callable_runner(arguments, cwd=str(cwd))
        except TypeError:
            return callable_runner(arguments)


def _command_result(value: Any) -> dict[str, Any]:
    if value is None:
        return {
            "ok": False,
            "returncode": 1,
            "stdout": "",
            "stderr": "runner returned no command result",
        }
    if isinstance(value, Mapping):
        returncode = value.get("returncode", value.get("code"))
        if returncode is None:
            status = str(value.get("status") or "").lower()
            if "ok" in value:
                ok = value.get("ok") is True
            else:
                ok = status in {"ok", "success", "succeeded"}
            returncode = 0 if ok else 1
        else:
            ok = int(returncode) == 0
        return {
            "ok": ok,
            "returncode": int(returncode),
            "stdout": str(value.get("stdout") or ""),
            "stderr": str(value.get("stderr") or value.get("error") or ""),
        }
    raw_returncode = getattr(value, "returncode", None)
    if raw_returncode is None:
        status = str(getattr(value, "status", "") or "").lower()
        ok = getattr(value, "ok", None) is True or status in {
            "ok",
            "success",
            "succeeded",
        }
        returncode = 0 if ok else 1
    else:
        returncode = int(raw_returncode)
        ok = returncode == 0
    return {
        "ok": ok,
        "returncode": returncode,
        "stdout": str(getattr(value, "stdout", "") or ""),
        "stderr": str(getattr(value, "stderr", "") or ""),
    }


def _redact_command(command: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False
    for item in command:
        text = str(item)
        if hide_next:
            redacted.append("<redacted>")
            hide_next = False
            continue
        option, separator, _value = text.partition("=")
        if separator and option.casefold() in _PASSWORD_OPTIONS:
            redacted.append(f"{option}=<redacted>")
            continue
        redacted.append(text)
        hide_next = text.casefold() in _PASSWORD_OPTIONS
    return redacted


def _command_secret_values(command: Sequence[str]) -> list[str]:
    secrets: list[str] = []
    capture_next = False
    for item in command:
        text = str(item)
        if capture_next:
            secrets.extend(_password_value_variants(text))
            capture_next = False
            continue
        option, separator, value = text.partition("=")
        if separator and option.casefold() in _PASSWORD_OPTIONS:
            secrets.extend(_password_value_variants(value))
            continue
        capture_next = text.casefold() in _PASSWORD_OPTIONS
    return sorted(set(secrets), key=len, reverse=True)


def _password_value_variants(value: str) -> list[str]:
    variants = [value] if value else []
    prefix, separator, payload = value.partition(":")
    if separator and prefix.casefold() in {"pass", "env", "file"} and payload:
        variants.append(payload)
    return variants


def _redact_command_text(value: Any, secrets: Sequence[str]) -> str:
    text = str(value or "")
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def _plan_path(plan: CapabilityPlan, name: str, fallback: Any = None) -> Path:
    value = plan.parameters.get(name, fallback)
    return Path(str(value or "")).expanduser().resolve()


def _add_check(
    checks: list[dict[str, Any]],
    errors: list[str],
    *,
    name: str,
    ok: bool,
    error: str,
    **details: Any,
) -> None:
    checks.append(
        {
            "name": name,
            "status": "ok" if ok else "failed",
            **_prune(details),
        }
    )
    if not ok:
        errors.append(error)


def _android_capability_boundary(
    *,
    action: Any,
    strategy: Any,
    verify_signature: bool = False,
    checks: Optional[Sequence[Mapping[str, Any]]] = None,
) -> dict[str, Any]:
    normalized_action = _normalize_action(action)
    normalized_strategy = _normalize_strategy(strategy)
    required_tools: list[str]
    if normalized_action == "verify" and verify_signature:
        provider_kind = "external_toolchain"
        operation_kind = "apksigner_signature_verify"
        required_tools = ["apksigner"]
        content_recompiled = False
        byte_preserving = True
        signature_verification = "apksigner"
    elif normalized_action == "rebuild" and normalized_strategy == _APKTOOL_REBUILD:
        provider_kind = "external_toolchain"
        operation_kind = "apktool_build_sign_verify"
        required_tools = ["apktool", "apksigner"]
        content_recompiled = True
        byte_preserving = False
        signature_verification = "apksigner"
    elif normalized_action == "unpack" and normalized_strategy == _APKTOOL_REBUILD:
        provider_kind = "external_toolchain"
        operation_kind = "apktool_decode"
        required_tools = ["apktool"]
        content_recompiled = False
        byte_preserving = False
        signature_verification = "not_performed"
    elif normalized_action == "verify":
        provider_kind = "builtin"
        operation_kind = "bounded_zip_static_verify"
        required_tools = []
        content_recompiled = False
        byte_preserving = True
        signature_verification = "presence_only"
    elif normalized_action == "unpack":
        provider_kind = "builtin"
        operation_kind = "bounded_zip_extract"
        required_tools = []
        content_recompiled = False
        byte_preserving = False
        signature_verification = "not_performed"
    else:
        provider_kind = "builtin"
        operation_kind = "byte_preserving_copy"
        required_tools = []
        content_recompiled = False
        byte_preserving = True
        signature_verification = "preserved_by_identical_sha256"

    tool_states: dict[str, str] = {}
    if not required_tools:
        dependency_state = "not_required"
    elif checks is None:
        dependency_state = "required"
    else:
        checks_by_name = {
            str(item.get("name") or ""): item
            for item in checks
            if isinstance(item, Mapping)
        }
        for tool in required_tools:
            tool_check = checks_by_name.get(f"{tool}_available", {})
            tool_states[tool] = str(tool_check.get("status") or "unavailable")
        dependency_state = (
            "available"
            if all(tool_states.get(tool) == "ok" for tool in required_tools)
            else "unavailable"
        )

    boundary = {
        "provider_kind": provider_kind,
        "operation_kind": operation_kind,
        "dependency_state": dependency_state,
        "required_tools": list(required_tools),
        "content_recompiled": content_recompiled,
        "byte_preserving": byte_preserving,
        "signature_verification": signature_verification,
        "target_code_executed": False,
        "members_extracted": normalized_action == "unpack",
        "source_modified": False,
    }
    if tool_states:
        boundary["tool_states"] = tool_states
    return boundary


def _plan_capability_boundary(
    plan: CapabilityPlan,
    *,
    checks: Optional[Sequence[Mapping[str, Any]]] = None,
) -> dict[str, Any]:
    return _android_capability_boundary(
        action=plan.action,
        strategy=plan.parameters.get("strategy"),
        verify_signature=_coerce_bool(
            plan.parameters.get("verify_signature"),
            default=False,
        ),
        checks=checks,
    )


def _capability_boundary_check(
    plan: CapabilityPlan,
    checks: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    boundary = _plan_capability_boundary(plan, checks=checks)
    return {
        "name": "capability_boundary",
        "status": "unavailable"
        if boundary["dependency_state"] == "unavailable"
        else "ok",
        **boundary,
    }


def _with_capability_boundary(
    payload: Mapping[str, Any],
    boundary: Mapping[str, Any],
) -> dict[str, Any]:
    result = _prune(payload)
    result["capability_boundary"] = _json_mapping(boundary)
    return result


def _non_execution_rollback_plan(reason: str) -> dict[str, Any]:
    return {
        "supported": False,
        "mode": "not_required",
        "completed": False,
        "reason": reason,
    }


def _manifest_entry(
    artifact: CapabilityArtifact,
    *,
    status: str,
    strategy: str,
) -> dict[str, Any]:
    return _prune(
        {
            "path": artifact.path,
            "kind": artifact.kind,
            "tool": "android_rebuild",
            "provider": AndroidRebuildProvider.provider_name,
            "status": status,
            "role": artifact.metadata.get("role") or "android-rebuild-artifact",
            "sha256": artifact.metadata.get("sha256"),
            "strategy": strategy,
        }
    )


def _input_evidence_entry(
    path: str | Path,
    snapshot: Mapping[str, Any],
    *,
    status: str,
    strategy: str,
) -> dict[str, Any]:
    return _prune(
        {
            "path": str(Path(path).expanduser().resolve()),
            "kind": "android-input-evidence",
            "tool": "android_rebuild",
            "provider": AndroidRebuildProvider.provider_name,
            "status": status,
            "role": "input-evidence",
            "sha256": snapshot.get("sha256"),
            "size": snapshot.get("size"),
            "entry_count": snapshot.get("entry_count"),
            "strategy": strategy,
            "read_only": True,
        }
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_tree(path: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    entry_count = 0
    total_size = 0
    entries = sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix())
    for entry in entries:
        relative = entry.relative_to(path).as_posix().encode("utf-8", errors="surrogateescape")
        entry_count += 1
        if entry.is_symlink():
            digest.update(b"L\0" + relative + b"\0")
            digest.update(os.readlink(entry).encode("utf-8", errors="surrogateescape"))
        elif entry.is_dir():
            digest.update(b"D\0" + relative + b"\0")
        elif entry.is_file():
            size = entry.stat().st_size
            total_size += size
            digest.update(b"F\0" + relative + b"\0" + str(size).encode("ascii") + b"\0")
            with entry.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest(), entry_count, total_size


def _has_apk_signing_block(path: Path) -> bool:
    magic = b"APK Sig Block 42"
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            handle.seek(max(0, size - (1024 * 1024)))
            return magic in handle.read()
    except OSError:
        return False


def _unsafe_archive_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = normalized.rstrip("/").split("/")
    return (
        not normalized
        or not path.parts
        or "\x00" in normalized
        or normalized.startswith("/")
        or "\\" in name
        or ".." in path.parts
        or any(part in {"", ".", ".."} for part in parts)
        or (path.parts and ":" in path.parts[0])
    )


def _archive_entry_issue(info: zipfile.ZipInfo) -> Optional[str]:
    if _unsafe_archive_name(info.filename):
        return "unsafe or non-canonical member path"
    unix_mode = (int(info.external_attr) >> 16) & 0xFFFF
    if unix_mode and stat.S_ISLNK(unix_mode):
        return "symbolic-link member"
    if int(info.flag_bits) & 0x1:
        return "encrypted member"
    if int(info.file_size) > _MAX_APK_MEMBER_BYTES:
        return f"declared member size exceeds limit {_MAX_APK_MEMBER_BYTES}"
    if not info.is_dir() and int(info.file_size) > 0:
        compressed_size = int(info.compress_size)
        if compressed_size <= 0:
            return "non-empty member has no compressed payload"
        ratio = int(info.file_size) / compressed_size
        if ratio > _MAX_APK_COMPRESSION_RATIO:
            return (
                "compression ratio exceeds limit "
                f"{_MAX_APK_COMPRESSION_RATIO}"
            )
    return None


def _verify_zip_members(
    archive: zipfile.ZipFile,
    infos: Sequence[zipfile.ZipInfo],
) -> tuple[Optional[str], Optional[str], int]:
    verified_bytes = 0
    for info in infos:
        if info.is_dir():
            continue
        member_bytes = 0
        try:
            with archive.open(info) as source_handle:
                while True:
                    chunk = source_handle.read(_ZIP_READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    member_bytes += len(chunk)
                    verified_bytes += len(chunk)
                    if member_bytes > _MAX_APK_MEMBER_BYTES:
                        return (
                            info.filename,
                            "member exceeds bounded verification limit",
                            verified_bytes,
                        )
                    if verified_bytes > _MAX_APK_UNCOMPRESSED_BYTES:
                        return (
                            info.filename,
                            "archive exceeds bounded verification limit",
                            verified_bytes,
                        )
            if member_bytes != int(info.file_size):
                return (
                    info.filename,
                    "member size differs from ZIP metadata",
                    verified_bytes,
                )
        except (
            OSError,
            RuntimeError,
            EOFError,
            ValueError,
            zipfile.BadZipFile,
            NotImplementedError,
            zlib.error,
        ) as exc:
            return (
                info.filename,
                str(exc) or exc.__class__.__name__,
                verified_bytes,
            )
    return None, None, verified_bytes


def _paths_equal(left: str | Path, right: str | Path) -> bool:
    left_path = Path(left).expanduser().resolve()
    right_path = Path(right).expanduser().resolve()
    try:
        if left_path.exists() and right_path.exists():
            return os.path.samefile(left_path, right_path)
    except OSError:
        pass
    return os.path.normcase(str(left_path)) == os.path.normcase(str(right_path))


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _path_contains(parent: str | Path, child: str | Path) -> bool:
    parent_path = Path(parent).expanduser().resolve()
    child_path = Path(child).expanduser().resolve()
    return _is_relative_to(child_path, parent_path)


def _same_snapshot(expected: Any, actual: Any) -> bool:
    expected_map = _json_mapping(expected)
    actual_map = _json_mapping(actual)
    expected_exists = bool(expected_map.get("exists"))
    actual_exists = bool(actual_map.get("exists"))
    if expected_exists != actual_exists:
        return False
    if not expected_exists:
        return True
    same_type = (
        bool(expected_map.get("is_file")) == bool(actual_map.get("is_file"))
        and bool(expected_map.get("is_dir")) == bool(actual_map.get("is_dir"))
    )
    return same_type and _hashes_equal(
        expected_map.get("sha256"), actual_map.get("sha256")
    )


def _writable_destination_parent(path: Path) -> bool:
    parent = path.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    return parent.is_dir() and os.access(parent, os.W_OK)


def _hashes_equal(left: Any, right: Any) -> bool:
    return bool(left and right) and str(left).casefold() == str(right).casefold()


def _valid_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(character in "0123456789abcdefABCDEF" for character in text)


def _bounded_timeout(value: Any, default: float) -> float:
    try:
        timeout = float(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        timeout = default
    return min(3600.0, max(1.0, timeout))


def _coerce_bool(value: Any, *, default: bool) -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _static_signature_result(inspection: Mapping[str, Any]) -> dict[str, Any]:
    signature = _json_mapping(inspection.get("signature"))
    present = bool(
        signature.get("v1_present") or signature.get("apk_signing_block_present")
    )
    return {
        "status": "present" if present else "unsigned",
        "mode": "python_static_inspection",
        "verified": False,
        "v1_present": bool(signature.get("v1_present")),
        "apk_signing_block_present": bool(signature.get("apk_signing_block_present")),
        "entries": signature.get("entries") or [],
    }


def _safe_segment(value: Any) -> str:
    text = "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "_"
        for character in str(value or "session")
    )
    return text[:80] or "session"


def _deduplicate(items: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(str(item) for item in items if item))


def _json_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    return {}


def _json_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "to_dict"):
        return _json_value(value.to_dict())
    return str(value)


def _prune(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _prune(item)
            for key, item in value.items()
            if item not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [_prune(item) for item in value if item not in (None, "", [], {})]
    return value
