"""Safe orchestration for patching one native ELF library inside an APK.

The APK layer deliberately does not implement another binary patch engine.
It validates and extracts one archive member, delegates ELF planning,
verification, apply, and rollback proof to the existing patch tools, then
repackages the result while preserving application entry metadata.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile
from typing import Any
import zipfile
import zlib

from ..patch.android_elf import (
    AndroidElfPatchError,
    parse_android_elf,
    plan_android_elf_patch,
    verify_android_elf_patch,
)
from .executor import ToolResult
from .patch import binary_patch_apply_plan, binary_patch_rollback_plan


_SCHEMA_VERSION = 1
_PLAN_NAME = "android_native_apk_patch"
_APK_SIGNATURE_MAGIC = b"APK Sig Block 42"
_MAX_JSON_BYTES = 32 * 1024 * 1024
_MAX_RELOCATION_EXAMPLES = 1_024
_MAX_SECTION_EXAMPLES = 1_024
_MAX_THUMB_BOUNDARY_SCAN_BYTES = 16 * 1024 * 1024
_MAX_PROCESS_OUTPUT = 64 * 1024
_SIGNATURE_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC")
_SUPPORTED_COMPRESSION = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
}
_ABI_EXPECTATIONS = {
    "armeabi": {"machine": 40, "bits": 32, "architecture": "arm"},
    "armeabi-v7a": {"machine": 40, "bits": 32, "architecture": "arm"},
    "arm64-v8a": {"machine": 183, "bits": 64, "architecture": "aarch64"},
}


class AndroidNativePatchError(ValueError):
    """Raised when an APK patch cannot be completed with checked evidence."""


@dataclass(frozen=True, slots=True)
class ApkPatchLimits:
    """Bounded ZIP limits used for every source and generated APK pass."""

    max_archive_bytes: int = 1024 * 1024 * 1024
    max_entries: int = 10_000
    max_member_bytes: int = 128 * 1024 * 1024
    max_total_uncompressed_bytes: int = 768 * 1024 * 1024
    max_compression_ratio: int = 1_000
    read_chunk_bytes: int = 1024 * 1024


DEFAULT_APK_PATCH_LIMITS = ApkPatchLimits()


def android_native_patch_apk(
    apk_path: str | Path,
    *,
    abi: str,
    library_path: str | None = None,
    library: str | None = None,
    lib_path: str | None = None,
    out_path: str | Path | None = None,
    artifact_dir: str | Path | None = None,
    out_dir: str | Path | None = None,
    virtual_address: int | str | None = None,
    relative_virtual_address: int | str | None = None,
    rva: int | str | None = None,
    file_offset: int | str | None = None,
    expected: str | bytes | None = None,
    replacement: str | bytes | None = None,
    instruction_mode: str = "auto",
    operation_id: str | None = None,
    intent: Mapping[str, Any] | None = None,
    sign: bool | None = None,
    signing: Mapping[str, Any] | None = None,
    apksigner: str | Path | None = None,
    apktool: str | Path | None = None,
    signing_timeout: float = 120.0,
    limits: ApkPatchLimits | Mapping[str, Any] | None = None,
) -> ToolResult:
    """Patch one ``lib/<abi>/*.so`` member and produce a new APK.

    ``apktool`` is intentionally not required for the built-in ZIP-copy path.
    When signing is requested, signed success is reported only after a real
    ``apksigner sign`` invocation and a subsequent successful
    ``apksigner verify`` of an APK containing signature material.
    """

    tool = "android_native_patch_apk"
    artifact_root: Path | None = None
    destination: Path | None = None
    output_published = False
    try:
        source = _require_apk(apk_path)
        normalized_abi = _normalize_abi(abi)
        member_name = _native_member_path(
            normalized_abi,
            _one_library_argument(library_path, library, lib_path),
        )
        bounded = _coerce_limits(limits)
        artifact_root = _artifact_root(source, artifact_dir=artifact_dir, out_dir=out_dir)
        destination = _output_path(source, out_path)
        _prepare_output_paths(source, destination, artifact_root)
        artifact_root.mkdir(parents=True)

        source_sha256 = _sha256_file(source)
        signing_requested = bool(signing) if sign is None else bool(sign)
        apksigner_path = _resolve_executable(apksigner, "apksigner")
        apktool_path = _resolve_executable(apktool, "apktool")
        toolchain = _toolchain_state(
            apksigner_path=apksigner_path,
            apktool_path=apktool_path,
        )

        extracted_path = artifact_root / "extracted" / Path(member_name).name
        source_scan = _scan_apk(
            source,
            member_name=member_name,
            extract_to=extracted_path,
            limits=bounded,
        )
        if source_scan["sha256"] != source_sha256:
            raise AndroidNativePatchError("source APK changed while it was being inspected")
        before_elf = _elf_baseline(extracted_path, normalized_abi)
        prepared_intent, address_evidence = _prepare_elf_patch_intent(
            extracted_path,
            virtual_address=virtual_address,
            relative_virtual_address=relative_virtual_address,
            rva=rva,
            file_offset=file_offset,
            expected=expected,
            replacement=replacement,
            instruction_mode=instruction_mode,
            operation_id=operation_id,
            intent=intent,
        )
        jni_risk = _jni_risk_evidence(
            extracted_path.read_bytes(),
            before_elf,
            file_offset=int(address_evidence["file_offset"]),
            size=int(address_evidence["size"]),
        )

        elf_plan_dir = artifact_root / "elf-plan"
        planned = plan_android_elf_patch(
            extracted_path,
            out_dir=elf_plan_dir,
            intent=prepared_intent,
        )
        _require_tool_ok(planned, "Android ELF patch planning")
        elf_plan_path = elf_plan_dir / "plan.json"
        elf_plan_evidence = _elf_evidence_bundle(elf_plan_dir, include_plan=True)
        _confirm_elf_plan_mapping(elf_plan_evidence["plan"], address_evidence)

        elf_verify_dir = artifact_root / "elf-verify"
        verified = verify_android_elf_patch(
            extracted_path,
            plan=elf_plan_path,
            out_dir=elf_verify_dir,
        )
        _require_tool_ok(verified, "Android ELF patch verification")
        elf_verify_evidence = _elf_evidence_bundle(elf_verify_dir, include_plan=False)

        patched_so = artifact_root / "patched" / Path(member_name).name
        applied = binary_patch_apply_plan(
            extracted_path,
            plan=elf_plan_path,
            out_path=patched_so,
            apply=True,
            artifact_dir=artifact_root / "elf-apply",
            plan_source_path=elf_plan_path,
        )
        _require_tool_ok(applied, "ELF patch apply")
        after_elf = _elf_baseline(patched_so, normalized_abi)
        elf_invariants = _elf_invariants(before_elf, after_elf, require_change=True)
        if not elf_invariants["valid"]:
            raise AndroidNativePatchError("; ".join(elf_invariants["errors"]))

        generic_rollback_path = artifact_root / "elf-apply" / "rollback.json"
        generic_rollback = _load_json_mapping(
            generic_rollback_path,
            label="generic ELF rollback manifest",
        )[0]
        rollback_proof_so = artifact_root / "elf-rollback-proof" / "restored.so"
        rollback_proof = binary_patch_rollback_plan(
            patched_so,
            rollback=generic_rollback_path,
            out_path=rollback_proof_so,
            apply=True,
            artifact_dir=artifact_root / "elf-rollback-proof" / "artifacts",
        )
        _require_tool_ok(rollback_proof, "ELF rollback proof")
        if _sha256_file(rollback_proof_so) != before_elf["sha256"]:
            raise AndroidNativePatchError("generic ELF rollback proof did not restore the original library")

        unsigned_apk = artifact_root / "unsigned-patched.apk"
        repack = _write_zip_copy(
            source,
            unsigned_apk,
            member_name=member_name,
            replacement_path=patched_so,
            limits=bounded,
            strip_signatures=True,
        )
        with tempfile.TemporaryDirectory(prefix="ra-apk-native-verify-") as temporary:
            unsigned_member = Path(temporary) / "unsigned-member.so"
            unsigned_scan = _scan_apk(
                unsigned_apk,
                member_name=member_name,
                extract_to=unsigned_member,
                limits=bounded,
            )
            unsigned_archive = _compare_application_entries(
                source_scan,
                unsigned_scan,
                member_name=member_name,
                expected_member_sha256=after_elf["sha256"],
            )
            if not unsigned_archive["valid"]:
                raise AndroidNativePatchError("; ".join(unsigned_archive["errors"]))
            packed_elf = _elf_baseline(unsigned_member, normalized_abi)
            packed_invariants = _elf_invariants(after_elf, packed_elf, require_change=False)
            if not packed_invariants["valid"]:
                raise AndroidNativePatchError("; ".join(packed_invariants["errors"]))

        expected_entries = _expected_application_entries(
            source_scan,
            unsigned_scan,
            member_name=member_name,
        )

        source_signing = _signature_with_verification(
            source_scan["signature"],
            source,
            apksigner_path,
            timeout=signing_timeout,
        )
        unsigned_signing = _signature_with_verification(
            unsigned_scan["signature"],
            unsigned_apk,
            apksigner_path,
            timeout=signing_timeout,
        )
        if unsigned_scan["signature"]["material_present"]:
            raise AndroidNativePatchError("unsigned ZIP-copy artifact still contains APK signature material")

        signing_state, final_candidate = _complete_signing(
            unsigned_apk,
            artifact_root=artifact_root,
            requested=signing_requested,
            signing=signing,
            apksigner_path=apksigner_path,
            timeout=signing_timeout,
            before=source_signing,
            unsigned=unsigned_signing,
        )

        with tempfile.TemporaryDirectory(prefix="ra-apk-native-final-") as temporary:
            final_member = Path(temporary) / "final-member.so"
            final_scan = _scan_apk(
                final_candidate,
                member_name=member_name,
                extract_to=final_member,
                limits=bounded,
            )
            final_archive = _compare_application_entries(
                source_scan,
                final_scan,
                member_name=member_name,
                expected_member_sha256=after_elf["sha256"],
            )
            if not final_archive["valid"]:
                raise AndroidNativePatchError("; ".join(final_archive["errors"]))
            final_entry_check = _compare_expected_entries(
                expected_entries,
                final_scan,
                comment_sha256=source_scan["comment_sha256"],
            )
            if not final_entry_check["valid"]:
                raise AndroidNativePatchError("; ".join(final_entry_check["errors"]))
            final_archive = _merge_archive_checks(final_archive, final_entry_check)
            final_elf = _elf_baseline(final_member, normalized_abi)
            final_invariants = _elf_invariants(after_elf, final_elf, require_change=False)
            if not final_invariants["valid"]:
                raise AndroidNativePatchError("; ".join(final_invariants["errors"]))

        if _sha256_file(source) != source_sha256:
            raise AndroidNativePatchError("source APK changed before output publication")
        _publish_copy_without_overwrite(final_candidate, destination)
        output_published = True
        patched_apk_sha256 = _sha256_file(destination)
        if patched_apk_sha256 != final_scan["sha256"]:
            raise AndroidNativePatchError("published APK hash differs from the verified candidate")
        if _sha256_file(source) != source_sha256:
            raise AndroidNativePatchError("source APK changed during output publication")

        elf_evidence = {
            "address_mapping": address_evidence,
            "section_risk": address_evidence["section_evidence"],
            "jni_risk": jni_risk,
            "planner": elf_plan_evidence,
            "independent_verification": elf_verify_evidence,
            "rollback_proof": {
                "path": str(rollback_proof_so),
                "sha256": _sha256_file(rollback_proof_so),
                "restored_source_sha256": before_elf["sha256"],
                "valid": _sha256_file(rollback_proof_so) == before_elf["sha256"],
            },
        }
        plan_payload = _apk_plan_payload(
            source=source,
            destination=destination,
            member_name=member_name,
            abi=normalized_abi,
            source_scan=source_scan,
            final_scan=final_scan,
            expected_entries=expected_entries,
            before_elf=before_elf,
            after_elf=after_elf,
            elf_invariants=elf_invariants,
            signing=signing_state,
            toolchain=toolchain,
            limits=bounded,
            elf_plan_path=elf_plan_path,
            generic_rollback_path=generic_rollback_path,
            elf_evidence=elf_evidence,
        )
        rollback_payload = _apk_rollback_payload(
            source=source,
            destination=destination,
            member_name=member_name,
            abi=normalized_abi,
            source_scan=source_scan,
            final_scan=final_scan,
            before_elf=before_elf,
            after_elf=after_elf,
            generic_rollback=generic_rollback,
            generic_rollback_path=generic_rollback_path,
            signing=signing_state,
            limits=bounded,
        )
        completion_status = (
            "dependency-gated"
            if signing_requested and signing_state["status"] != "verified-signed"
            else "ok"
        )
        verify_payload = _initial_verify_payload(
            source=source,
            destination=destination,
            member_name=member_name,
            source_sha256=source_sha256,
            final_scan=final_scan,
            archive_check=final_archive,
            elf_check=final_invariants,
            rollback_proof_sha256=_sha256_file(rollback_proof_so),
            expected_restored_sha256=before_elf["sha256"],
            signing=signing_state,
            completion_status=completion_status,
        )
        if not verify_payload["valid"]:
            raise AndroidNativePatchError("final APK patch verification did not pass")

        plan_artifact = artifact_root / "native-patch-plan.json"
        verify_artifact = artifact_root / "native-patch-verify.json"
        rollback_artifact = artifact_root / "rollback.json"
        _write_json(plan_artifact, plan_payload)
        _write_json(verify_artifact, verify_payload)
        _write_json(rollback_artifact, rollback_payload)
        artifacts = _patch_artifacts(
            destination=destination,
            unsigned_apk=unsigned_apk,
            plan_path=plan_artifact,
            verify_path=verify_artifact,
            rollback_path=rollback_artifact,
            elf_plan_path=elf_plan_path,
            generic_rollback_path=generic_rollback_path,
            signed=bool(signing_state["signed"]),
            evidence_paths=_elf_artifact_paths(
                artifact_root,
                extracted_path=extracted_path,
                patched_so=patched_so,
                rollback_proof_so=rollback_proof_so,
            ),
        )
        if _sha256_file(source, max_bytes=bounded.max_archive_bytes) != source_sha256:
            raise AndroidNativePatchError("source APK changed before patch completion")
        if _sha256_file(destination, max_bytes=bounded.max_archive_bytes) != patched_apk_sha256:
            raise AndroidNativePatchError("published APK changed before patch completion")
        return ToolResult(
            tool=tool,
            status=completion_status,
            data={
                "status": completion_status,
                "valid": True,
                "source_apk_path": str(source),
                "patched_apk_path": str(destination),
                "source_sha256": source_sha256,
                "patched_sha256": patched_apk_sha256,
                "original_apk_unchanged": True,
                "abi": normalized_abi,
                "library_path": member_name,
                "elf": {
                    "before": before_elf,
                    "after": after_elf,
                    "invariants": elf_invariants,
                    "evidence": elf_evidence,
                },
                "archive": final_archive,
                "repack": repack,
                "signing": signing_state,
                "toolchain": toolchain,
                "plan_path": str(plan_artifact),
                "verify_path": str(verify_artifact),
                "rollback_path": str(rollback_artifact),
                "artifacts": artifacts,
            },
        )
    except (
        AndroidElfPatchError,
        AndroidNativePatchError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
    ) as exc:
        if output_published and destination is not None:
            _remove_file(destination)
        if artifact_root is not None and artifact_root.exists():
            shutil.rmtree(artifact_root, ignore_errors=True)
        return _failure(tool, exc, apk_path)


def verify_android_native_patch_apk(
    apk_path: str | Path,
    *,
    plan: Mapping[str, Any] | str | Path,
    out_dir: str | Path | None = None,
    apksigner: str | Path | None = None,
    signing_timeout: float = 120.0,
    limits: ApkPatchLimits | Mapping[str, Any] | None = None,
) -> ToolResult:
    """Revalidate a patched APK against an APK-level native patch plan."""

    tool = "android_native_patch_apk_verify"
    try:
        target = _require_apk(apk_path)
        plan_payload, plan_parent = _load_json_mapping(plan, label="APK native patch plan")
        _validate_apk_plan(plan_payload)
        bounded = _coerce_limits(
            limits if limits is not None else plan_payload.get("limits")
        )
        target_plan = _mapping(plan_payload.get("target"), "plan.target")
        abi = _normalize_abi(_required_text(target_plan.get("abi"), "plan.target.abi"))
        member_name = _canonical_planned_member(
            abi,
            target_plan.get("library_path"),
            "plan.target.library_path",
        )
        expected_output = _mapping(plan_payload.get("output"), "plan.output")
        expected_sha256 = _required_sha256(expected_output.get("sha256"), "plan.output.sha256")
        expected_entries = _sequence_of_mappings(
            _mapping(plan_payload.get("archive"), "plan.archive").get("expected_application_entries"),
            "plan.archive.expected_application_entries",
        )
        if len(expected_entries) > bounded.max_entries:
            raise AndroidNativePatchError(
                "plan application entry count exceeds the configured APK entry limit"
            )
        expected_comment = str(_mapping(plan_payload.get("archive"), "plan.archive").get("comment_sha256") or "")
        expected_elf = _mapping(_mapping(plan_payload.get("elf"), "plan.elf").get("after"), "plan.elf.after")

        with tempfile.TemporaryDirectory(prefix="ra-apk-native-reverify-") as temporary:
            member = Path(temporary) / "member.so"
            scan = _scan_apk(target, member_name=member_name, extract_to=member, limits=bounded)
            observed_elf = _elf_baseline(member, abi)
        errors: list[str] = []
        if scan["sha256"] != expected_sha256:
            errors.append("patched APK SHA-256 does not match the plan")
        archive_check = _compare_expected_entries(
            expected_entries,
            scan,
            comment_sha256=expected_comment,
        )
        errors.extend(archive_check["errors"])
        elf_check = _expected_elf_matches(expected_elf, observed_elf)
        errors.extend(elf_check["errors"])

        expected_signing = _mapping(plan_payload.get("signing"), "plan.signing")
        apksigner_path = _resolve_executable(apksigner, "apksigner")
        signing_check = _verify_expected_signing(
            target,
            scan["signature"],
            expected_signing,
            apksigner_path=apksigner_path,
            timeout=signing_timeout,
        )
        errors.extend(signing_check["errors"])

        source_check = _verify_source_identity(plan_payload)
        errors.extend(source_check["errors"])
        valid = not errors
        completion_status = (
            "dependency-gated"
            if valid and signing_check.get("dependency_gated")
            else ("ok" if valid else "failed")
        )
        report = {
            "schema_version": _SCHEMA_VERSION,
            "kind": "android_native_apk_patch_verify",
            "status": completion_status,
            "valid": valid,
            "target": {
                "path": str(target),
                "sha256": scan["sha256"],
                "library_path": member_name,
                "abi": abi,
            },
            "checks": [
                _check("apk_sha256", scan["sha256"] == expected_sha256),
                _check("archive_entries", archive_check["valid"], archive_check),
                _check("elf_baseline", elf_check["valid"], elf_check),
                _check("source_unchanged", source_check["valid"], source_check),
                _check(
                    "signing",
                    signing_check["valid"],
                    signing_check,
                    status=signing_check.get("check_status"),
                ),
            ],
            "errors": errors,
            "archive": archive_check,
            "elf": {"expected": dict(expected_elf), "observed": observed_elf},
            "signing": signing_check,
            "source": source_check,
        }
        artifact_root = (
            Path(out_dir).expanduser().resolve()
            if out_dir is not None
            else plan_parent or target.parent / f"{target.stem}.native-patch-verify"
        )
        artifact_root.mkdir(parents=True, exist_ok=True)
        verify_path = artifact_root / "native-patch-verify.json"
        _write_json(verify_path, report)
        report["verify_path"] = str(verify_path)
        report["artifacts"] = [_artifact(verify_path, "android-native-patch-verify")]
        return ToolResult(
            tool=tool,
            status=completion_status,
            error=None if valid else "; ".join(errors),
            data=report,
        )
    except (
        AndroidElfPatchError,
        AndroidNativePatchError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
    ) as exc:
        return _failure(tool, exc, apk_path)


def rollback_android_native_patch_apk(
    apk_path: str | Path,
    *,
    rollback: Mapping[str, Any] | str | Path,
    out_path: str | Path,
    artifact_dir: str | Path | None = None,
    out_dir: str | Path | None = None,
    original_apk: str | Path | None = None,
    apksigner: str | Path | None = None,
    signing_timeout: float = 120.0,
    limits: ApkPatchLimits | Mapping[str, Any] | None = None,
) -> ToolResult:
    """Restore a patched APK, proving the native rollback with the generic engine.

    If the immutable source APK named by the rollback artifact is still
    available and hash-identical, it is copied as the exact rollback output.
    Otherwise an unsigned logical rollback is rebuilt from the patched APK.
    """

    tool = "android_native_patch_apk_rollback"
    artifact_root: Path | None = None
    destination: Path | None = None
    output_published = False
    try:
        patched_apk = _require_apk(apk_path)
        payload, _ = _load_json_mapping(rollback, label="APK native rollback manifest")
        _validate_apk_rollback(payload)
        bounded = _coerce_limits(
            limits if limits is not None else payload.get("limits")
        )
        target = _mapping(payload.get("target"), "rollback.target")
        abi = _normalize_abi(_required_text(target.get("abi"), "rollback.target.abi"))
        member_name = _canonical_planned_member(
            abi,
            target.get("library_path"),
            "rollback.target.library_path",
        )
        expected_patched_apk = _required_sha256(
            _mapping(payload.get("patched_apk"), "rollback.patched_apk").get("sha256"),
            "rollback.patched_apk.sha256",
        )
        expected_original_so = _required_sha256(
            _mapping(payload.get("elf"), "rollback.elf").get("source_sha256"),
            "rollback.elf.source_sha256",
        )
        expected_patched_so = _required_sha256(
            _mapping(payload.get("elf"), "rollback.elf").get("patched_sha256"),
            "rollback.elf.patched_sha256",
        )
        generic_rollback = _mapping(
            payload.get("generic_elf_rollback"),
            "rollback.generic_elf_rollback",
        )

        destination = Path(out_path).expanduser().resolve()
        artifact_root = _rollback_artifact_root(
            patched_apk,
            artifact_dir=artifact_dir,
            out_dir=out_dir,
        )
        _prepare_output_paths(patched_apk, destination, artifact_root)
        artifact_root.mkdir(parents=True)

        with tempfile.TemporaryDirectory(prefix="ra-apk-native-rollback-") as temporary:
            work = Path(temporary)
            patched_so = work / "patched.so"
            patched_scan = _scan_apk(
                patched_apk,
                member_name=member_name,
                extract_to=patched_so,
                limits=bounded,
            )
            if patched_scan["sha256"] != expected_patched_apk:
                raise AndroidNativePatchError("patched APK SHA-256 does not match rollback evidence")
            if _sha256_file(patched_so) != expected_patched_so:
                raise AndroidNativePatchError("patched native library SHA-256 does not match rollback evidence")

            restored_so = artifact_root / "restored" / Path(member_name).name
            generic_result = binary_patch_rollback_plan(
                patched_so,
                rollback=generic_rollback,
                out_path=restored_so,
                apply=True,
                artifact_dir=artifact_root / "elf-rollback",
            )
            _require_tool_ok(generic_result, "ELF rollback")
            if _sha256_file(restored_so) != expected_original_so:
                raise AndroidNativePatchError("ELF rollback output does not match the original library hash")
            restored_elf = _elf_baseline(restored_so, abi)

            source_identity = _mapping(payload.get("source_apk"), "rollback.source_apk")
            source_candidate = (
                Path(original_apk).expanduser().resolve()
                if original_apk is not None
                else Path(str(source_identity.get("path") or "")).expanduser().resolve()
            )
            exact_source = False
            source_scan: dict[str, Any] | None = None
            candidate_output = work / "rollback.apk"
            if source_candidate.is_file() and _sha256_file(source_candidate) == source_identity.get("sha256"):
                source_member = work / "source.so"
                source_scan = _scan_apk(
                    source_candidate,
                    member_name=member_name,
                    extract_to=source_member,
                    limits=bounded,
                )
                if _sha256_file(source_member) != expected_original_so:
                    raise AndroidNativePatchError("source APK library does not match rollback evidence")
                shutil.copyfile(source_candidate, candidate_output)
                exact_source = True
            else:
                _write_zip_copy(
                    patched_apk,
                    candidate_output,
                    member_name=member_name,
                    replacement_path=restored_so,
                    limits=bounded,
                    strip_signatures=True,
                )

            output_member = work / "output.so"
            output_scan = _scan_apk(
                candidate_output,
                member_name=member_name,
                extract_to=output_member,
                limits=bounded,
            )
            if _sha256_file(output_member) != expected_original_so:
                raise AndroidNativePatchError("rollback APK does not contain the restored native library")
            output_elf = _elf_baseline(output_member, abi)
            elf_check = _elf_invariants(restored_elf, output_elf, require_change=False)
            if not elf_check["valid"]:
                raise AndroidNativePatchError("; ".join(elf_check["errors"]))
            if exact_source and output_scan["sha256"] != source_identity.get("sha256"):
                raise AndroidNativePatchError("exact rollback copy does not match source APK SHA-256")
            if exact_source:
                archive_check = {
                    "valid": True,
                    "errors": [],
                    "mode": "exact-source-copy",
                }
            else:
                archive_check = _compare_application_entries(
                    patched_scan,
                    output_scan,
                    member_name=member_name,
                    expected_member_sha256=expected_original_so,
                )
                if not archive_check["valid"]:
                    raise AndroidNativePatchError("; ".join(archive_check["errors"]))

            _publish_copy_without_overwrite(candidate_output, destination)
            output_published = True

        restored_apk_sha256 = _sha256_file(
            destination,
            max_bytes=bounded.max_archive_bytes,
        )
        if restored_apk_sha256 != output_scan["sha256"]:
            raise AndroidNativePatchError("published rollback APK differs from its verified candidate")
        apksigner_path = _resolve_executable(apksigner, "apksigner")
        signing_state = _signature_with_verification(
            output_scan["signature"],
            destination,
            apksigner_path,
            timeout=signing_timeout,
        )
        report = {
            "schema_version": _SCHEMA_VERSION,
            "kind": "android_native_apk_rollback_verify",
            "status": "ok",
            "valid": True,
            "restoration_mode": (
                "exact-source-copy" if exact_source else "logical-unsigned-repack"
            ),
            "patched_apk": {
                "path": str(patched_apk),
                "sha256": patched_scan["sha256"],
            },
            "restored_apk": {
                "path": str(destination),
                "sha256": restored_apk_sha256,
            },
            "target": {"abi": abi, "library_path": member_name},
            "elf": {
                "source_sha256": expected_original_so,
                "restored_sha256": _sha256_file(restored_so),
                "invariants": elf_check,
            },
            "signing": signing_state,
            "archive": archive_check,
            "checks": [
                _check("patched_apk_hash", True),
                _check("generic_elf_rollback", True),
                _check("restored_library_hash", True),
                _check("archive_content_and_metadata", bool(archive_check["valid"]), archive_check),
                _check("rollback_apk_materialized", True),
            ],
            "errors": [],
        }
        verify_path = artifact_root / "rollback-verify.json"
        _write_json(verify_path, report)
        artifacts = [
            _artifact(destination, "android-native-rollback-apk"),
            _artifact(restored_so, "restored-native-library"),
            _artifact(verify_path, "android-native-rollback-verify"),
        ]
        if _sha256_file(patched_apk, max_bytes=bounded.max_archive_bytes) != expected_patched_apk:
            raise AndroidNativePatchError("patched APK changed before rollback completion")
        if _sha256_file(destination, max_bytes=bounded.max_archive_bytes) != restored_apk_sha256:
            raise AndroidNativePatchError("restored APK changed before rollback completion")
        return ToolResult(
            tool=tool,
            status="ok",
            data={**report, "verify_path": str(verify_path), "artifacts": artifacts},
        )
    except (
        AndroidElfPatchError,
        AndroidNativePatchError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
    ) as exc:
        if output_published and destination is not None:
            _remove_file(destination)
        if artifact_root is not None and artifact_root.exists():
            shutil.rmtree(artifact_root, ignore_errors=True)
        return _failure(tool, exc, apk_path)


# Compatibility aliases keep direct callers independent from word order.
patch_android_native_apk = android_native_patch_apk
patch_apk_native_library = android_native_patch_apk
verify_android_native_apk_patch = verify_android_native_patch_apk
rollback_android_native_apk_patch = rollback_android_native_patch_apk


def _prepare_elf_patch_intent(
    path: Path,
    *,
    virtual_address: int | str | None,
    relative_virtual_address: int | str | None,
    rva: int | str | None,
    file_offset: int | str | None,
    expected: str | bytes | None,
    replacement: str | bytes | None,
    instruction_mode: str,
    operation_id: str | None,
    intent: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Normalize one explicit selector and prove its ELF instruction range."""

    data = path.read_bytes()
    image = parse_android_elf(data)
    normalized = dict(intent or {})
    aliases = {
        "va": "virtual_address",
        "address": "virtual_address",
        "offset": "file_offset",
        "rva": "relative_virtual_address",
        "preimage": "expected",
    }
    for alias, canonical in aliases.items():
        if alias not in normalized:
            continue
        if canonical in normalized and normalized[canonical] != normalized[alias]:
            raise AndroidNativePatchError(
                f"patch intent contains conflicting {alias} and {canonical} values"
            )
        normalized.setdefault(canonical, normalized[alias])
        normalized.pop(alias, None)

    explicit_selectors = [
        ("virtual_address", virtual_address),
        ("relative_virtual_address", relative_virtual_address),
        ("rva", rva),
        ("file_offset", file_offset),
    ]
    provided_selectors = [(name, value) for name, value in explicit_selectors if value is not None]
    if len(provided_selectors) > 1:
        raise AndroidNativePatchError(
            "provide exactly one APK ELF selector: virtual_address, relative_virtual_address/rva, or file_offset"
        )
    if provided_selectors:
        name, value = provided_selectors[0]
        canonical = "relative_virtual_address" if name == "rva" else name
        normalized[canonical] = value
    if replacement is not None:
        normalized["replacement"] = replacement
    if expected is not None:
        normalized["expected"] = expected
    if "instruction_mode" not in normalized and "mode" not in normalized:
        normalized["instruction_mode"] = instruction_mode
    if operation_id is not None:
        normalized["id"] = operation_id

    selectors = [
        name
        for name in ("virtual_address", "relative_virtual_address", "file_offset")
        if normalized.get(name) is not None
    ]
    if len(selectors) != 1:
        raise AndroidNativePatchError(
            "provide exactly one APK ELF selector: virtual_address, relative_virtual_address/rva, or file_offset"
        )
    if normalized.get("expected") is None:
        raise AndroidNativePatchError(
            "expected bytes are required for an APK native patch"
        )

    replacement_bytes = _hex_byte_value(normalized.get("replacement"), field="replacement")
    expected_bytes = _hex_byte_value(normalized.get("expected"), field="expected")
    if len(replacement_bytes) != len(expected_bytes):
        raise AndroidNativePatchError("expected bytes length must equal replacement length")
    size = len(replacement_bytes)
    image_base = min(segment.virtual_address for segment in image.load_segments)
    requested_mode = str(normalized.get("instruction_mode", normalized.get("mode", "auto")))
    selector = selectors[0]

    if selector == "file_offset":
        requested_offset = _nonnegative_value(normalized[selector], field=selector)
        canonical_va = image.file_offset_to_virtual_address(requested_offset, size)
        mode = _native_instruction_mode(image, requested_mode, canonical_va)
        canonical_offset = requested_offset
        requested_va = canonical_va
        selector_value = requested_offset
        selector_name = "file_offset"
    else:
        selector_value = _nonnegative_value(normalized[selector], field=selector)
        requested_va = (
            image_base + selector_value
            if selector == "relative_virtual_address"
            else selector_value
        )
        mode = _native_instruction_mode(image, requested_mode, requested_va)
        canonical_offset = image.virtual_address_to_file_offset(
            requested_va,
            size,
            instruction_mode=mode,
        )
        canonical_va = image.file_offset_to_virtual_address(canonical_offset, size)
        selector_name = "rva" if selector == "relative_virtual_address" else "virtual_address"

    boundary = _instruction_boundary_evidence(
        image,
        data,
        mode=mode,
        virtual_address=canonical_va,
        file_offset=canonical_offset,
        size=size,
    )
    observed = data[canonical_offset : canonical_offset + size]
    if observed != expected_bytes:
        raise AndroidNativePatchError(
            "expected bytes do not match the selected ELF preimage"
        )

    normalized.pop("virtual_address", None)
    normalized.pop("relative_virtual_address", None)
    normalized.pop("file_offset", None)
    normalized.pop("mode", None)
    if selector_name == "file_offset":
        normalized["file_offset"] = canonical_offset
    else:
        normalized["virtual_address"] = requested_va
    normalized["expected"] = expected_bytes.hex()
    normalized["replacement"] = replacement_bytes.hex()
    normalized["instruction_mode"] = mode

    segment = image.segment_for_file_range(canonical_offset, size)
    canonical_rva = canonical_va - image_base
    evidence = {
        "selector": selector_name,
        "selector_value": selector_value,
        "selector_value_hex": f"0x{selector_value:X}",
        "image_base": image_base,
        "image_base_hex": f"0x{image_base:X}",
        "image_base_definition": "minimum_pt_load_virtual_address",
        "requested_virtual_address": requested_va,
        "canonical_virtual_address": canonical_va,
        "canonical_virtual_address_hex": f"0x{canonical_va:X}",
        "relative_virtual_address": canonical_rva,
        "relative_virtual_address_hex": f"0x{canonical_rva:X}",
        "file_offset": canonical_offset,
        "file_offset_hex": f"0x{canonical_offset:X}",
        "size": size,
        "instruction_mode": mode,
        "expected": expected_bytes.hex(),
        "replacement": replacement_bytes.hex(),
        "expected_source": "caller-supplied",
        "preimage_verified": True,
        "segment": segment.to_dict(),
        "section_evidence": boundary["section_evidence"],
        "instruction_boundary": boundary,
    }
    return normalized, evidence


def _native_instruction_mode(image: Any, requested: str, address: int) -> str:
    normalized = requested.strip().casefold().replace("-", "")
    normalized = {"arm32": "arm", "thumb2": "thumb", "arm64": "aarch64"}.get(
        normalized,
        normalized,
    )
    if image.architecture == "aarch64":
        if normalized in {"", "auto", "aarch64"}:
            return "aarch64"
        raise AndroidNativePatchError("AArch64 ELF patches require instruction_mode=aarch64")
    if normalized in {"", "auto"}:
        if address & 1:
            return "thumb"
        if image.entrypoint & 1 and address == (image.entrypoint & ~1):
            return "thumb"
        return "arm"
    if normalized not in {"arm", "thumb"}:
        raise AndroidNativePatchError("ARM ELF patches require instruction_mode=arm or thumb")
    if normalized == "arm" and address & 1:
        raise AndroidNativePatchError(
            "an odd ARM virtual address carries Thumb state; use instruction_mode=thumb"
        )
    return normalized


def _instruction_boundary_evidence(
    image: Any,
    data: bytes,
    *,
    mode: str,
    virtual_address: int,
    file_offset: int,
    size: int,
) -> dict[str, Any]:
    section_evidence = _target_section_evidence(image, file_offset=file_offset, size=size)
    if mode != "thumb":
        if virtual_address % 4:
            raise AndroidNativePatchError(
                f"{mode} virtual address 0x{virtual_address:X} is not 4-byte aligned"
            )
        if file_offset % 4:
            raise AndroidNativePatchError(
                f"{mode} file offset 0x{file_offset:X} is not 4-byte aligned"
            )
        if size % 4:
            raise AndroidNativePatchError(
                f"{mode} replacement size {size} is not a multiple of 4"
            )
        return {
            "valid": True,
            "mode": mode,
            "decoder": "fixed-width-4-byte",
            "start_boundary": True,
            "end_boundary": True,
            "instruction_widths": [4] * (size // 4),
            "section_evidence": section_evidence,
        }

    executable = [
        item
        for item in section_evidence["containing_sections"]
        if item["executable"] and item["file_backed"]
    ]
    if len(executable) != 1:
        raise AndroidNativePatchError(
            "Thumb instruction boundaries require exactly one containing file-backed executable section"
        )
    section = executable[0]
    section_start = int(section["offset"])
    section_end = section_start + int(section["size"])
    if file_offset - section_start > _MAX_THUMB_BOUNDARY_SCAN_BYTES:
        raise AndroidNativePatchError(
            "Thumb instruction boundary scan exceeds the configured proof limit"
        )
    if section_start % 2 or file_offset % 2 or size % 2:
        raise AndroidNativePatchError("Thumb patch ranges must be 2-byte aligned")

    cursor = section_start
    decoded = 0
    while cursor < file_offset:
        width = _thumb_instruction_width(data, cursor, section_end)
        if cursor + width > file_offset:
            raise AndroidNativePatchError(
                "Thumb patch starts inside a 32-bit Thumb-2 instruction"
            )
        cursor += width
        decoded += 1
    if cursor != file_offset:
        raise AndroidNativePatchError("Thumb patch start is not an instruction boundary")

    end = file_offset + size
    widths: list[int] = []
    while cursor < end:
        width = _thumb_instruction_width(data, cursor, section_end)
        if cursor + width > end:
            raise AndroidNativePatchError(
                "Thumb patch ends inside a 32-bit Thumb-2 instruction"
            )
        widths.append(width)
        cursor += width
        decoded += 1
    if cursor != end:
        raise AndroidNativePatchError("Thumb patch end is not an instruction boundary")
    return {
        "valid": True,
        "mode": "thumb",
        "decoder": "thumb-halfword-prefix-width-decoder",
        "start_boundary": True,
        "end_boundary": True,
        "instruction_widths": widths,
        "decoded_instruction_count": decoded,
        "section_evidence": section_evidence,
    }


def _thumb_instruction_width(data: bytes, offset: int, section_end: int) -> int:
    if offset < 0 or offset + 2 > section_end or offset + 2 > len(data):
        raise AndroidNativePatchError("truncated Thumb instruction in executable section")
    halfword = int.from_bytes(data[offset : offset + 2], "little")
    width = 4 if (halfword >> 11) in {0b11101, 0b11110, 0b11111} else 2
    if offset + width > section_end or offset + width > len(data):
        raise AndroidNativePatchError("truncated 32-bit Thumb-2 instruction")
    return width


def _target_section_evidence(
    image: Any,
    *,
    file_offset: int,
    size: int,
) -> dict[str, Any]:
    end = file_offset + size
    overlapping: list[dict[str, Any]] = []
    containing: list[dict[str, Any]] = []
    for section in image.sections:
        snapshot = _section_snapshot(section)
        section_end = section.offset + section.size
        if section.size and file_offset < section_end and section.offset < end:
            overlapping.append(snapshot)
        if section.size and section.offset <= file_offset and end <= section_end:
            containing.append(snapshot)
    executable = [item for item in containing if item["executable"] and item["file_backed"]]
    risks: list[str] = []
    if not containing:
        risks.append("patch range is not described by a containing ELF section")
    if not executable:
        risks.append("patch range is not proved to be inside an executable file-backed section")
    if len(containing) > 1:
        risks.append("patch range has overlapping ELF section descriptions")
    return {
        "section_table_present": bool(image.section_header_count),
        "section_count": len(image.sections),
        "containing_sections": containing,
        "overlapping_sections": overlapping,
        "executable_section_proved": len(executable) == 1,
        "risks": risks,
        "status": "proved" if not risks else "review-required",
    }


def _section_snapshot(section: Any) -> dict[str, Any]:
    return {
        "index": int(section.index),
        "type": int(section.type),
        "flags": int(section.flags),
        "address": int(section.address),
        "offset": int(section.offset),
        "size": int(section.size),
        "alignment": int(section.alignment),
        "entry_size": int(section.entry_size),
        "executable": bool(int(section.flags) & 0x4),
        "allocated": bool(int(section.flags) & 0x2),
        "writable": bool(int(section.flags) & 0x1),
        "file_backed": int(section.type) != 8,
    }


def _jni_risk_evidence(
    data: bytes,
    baseline: Mapping[str, Any],
    *,
    file_offset: int,
    size: int,
) -> dict[str, Any]:
    end = file_offset + size
    intersections: list[dict[str, Any]] = []
    locations: list[dict[str, Any]] = []
    for export in baseline.get("jni_exports") or []:
        name = str(export)
        needle = name.encode("utf-8", errors="strict") + b"\x00"
        start = 0
        found = 0
        while found < 64:
            offset = data.find(needle, start)
            if offset < 0:
                break
            item = {"name": name, "file_offset": offset, "size": len(needle)}
            locations.append(item)
            if file_offset < offset + len(needle) and offset < end:
                intersections.append(item)
            start = offset + 1
            found += 1
    if intersections:
        severity = "critical"
        status = "intersects-jni-name"
    elif baseline.get("jni_export_count"):
        severity = "medium"
        status = "jni-surface-present"
    else:
        severity = "info"
        status = "no-jni-surface-detected"
    return {
        "status": status,
        "severity": severity,
        "export_count": int(baseline.get("jni_export_count") or 0),
        "exports": list(baseline.get("jni_exports") or []),
        "symbol_source": baseline.get("jni_symbol_source"),
        "name_locations": locations,
        "patch_intersections": intersections,
        "direct_name_intersection": bool(intersections),
        "post_patch_exports_must_match": True,
    }


def _elf_evidence_bundle(root: Path, *, include_plan: bool) -> dict[str, Any]:
    names = ["verify.json", "risk_report.json", "rollback_plan.json"]
    if include_plan:
        names.insert(0, "plan.json")
    payloads: dict[str, Any] = {}
    artifacts: list[dict[str, Any]] = []
    key_by_name = {
        "plan.json": "plan",
        "verify.json": "verification",
        "risk_report.json": "risk_report",
        "rollback_plan.json": "rollback_plan",
    }
    kind_by_name = {
        "plan.json": "android-elf-patch-plan",
        "verify.json": "android-elf-patch-verification",
        "risk_report.json": "android-elf-patch-risk-report",
        "rollback_plan.json": "android-elf-patch-rollback-plan",
    }
    for name in names:
        path = root / name
        payload = _load_json_mapping(path, label=f"ELF evidence {name}")[0]
        payloads[key_by_name[name]] = payload
        artifacts.append(_artifact(path, kind_by_name[name]))
    payloads["artifacts"] = artifacts
    return payloads


def _confirm_elf_plan_mapping(
    plan: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> None:
    operations = plan.get("operations")
    if not isinstance(operations, list) or len(operations) != 1 or not isinstance(operations[0], Mapping):
        raise AndroidNativePatchError("ELF planner did not emit exactly one checked operation")
    operation = operations[0]
    checks = {
        "offset": evidence["file_offset"],
        "virtual_address": evidence["canonical_virtual_address"],
        "expected": evidence["expected"],
        "replacement": evidence["replacement"],
        "instruction_mode": evidence["instruction_mode"],
    }
    for field, expected_value in checks.items():
        actual = operation.get(field)
        if isinstance(expected_value, str) and field in {"expected", "replacement", "instruction_mode"}:
            matches = str(actual).casefold() == expected_value.casefold()
        else:
            matches = actual == expected_value
        if not matches:
            raise AndroidNativePatchError(
                f"ELF planner operation does not match APK address evidence: {field}"
            )


def _merge_archive_checks(
    preservation: Mapping[str, Any],
    exact: Mapping[str, Any],
) -> dict[str, Any]:
    errors = [*preservation.get("errors", []), *exact.get("errors", [])]
    return {
        **dict(preservation),
        "valid": not errors,
        "errors": errors,
        "planned_entry_evidence": dict(exact),
        "crc_size_compression_verified": bool(exact.get("valid")),
    }


def _scan_apk(
    path: Path,
    *,
    member_name: str,
    extract_to: Path,
    limits: ApkPatchLimits,
) -> dict[str, Any]:
    file_size = path.stat().st_size
    if file_size > limits.max_archive_bytes:
        raise AndroidNativePatchError(
            f"APK size exceeds limit {limits.max_archive_bytes}: {file_size}"
        )
    initial_sha256 = _sha256_file(path, max_bytes=limits.max_archive_bytes)
    entries: list[dict[str, Any]] = []
    extract_to.parent.mkdir(parents=True, exist_ok=True)
    if extract_to.exists():
        raise AndroidNativePatchError(f"native extraction destination already exists: {extract_to}")
    target_seen = False
    try:
        with zipfile.ZipFile(path, "r", allowZip64=True) as archive:
            infos = archive.infolist()
            _validate_zip_catalog(infos, limits=limits)
            names = [info.filename for info in infos]
            if names.count("AndroidManifest.xml") != 1:
                raise AndroidNativePatchError("APK must contain exactly one AndroidManifest.xml")
            if names.count(member_name) != 1:
                raise AndroidNativePatchError(
                    f"APK must contain exactly one requested native library: {member_name}"
                )
            total_read = 0
            for info in infos:
                digest = hashlib.sha256()
                member_read = 0
                output_handle = None
                if info.filename == member_name:
                    if info.is_dir():
                        raise AndroidNativePatchError("requested native library is a directory entry")
                    output_handle = extract_to.open("xb")
                    target_seen = True
                try:
                    if not info.is_dir():
                        with archive.open(info, "r") as source_handle:
                            while True:
                                chunk = source_handle.read(limits.read_chunk_bytes)
                                if not chunk:
                                    break
                                member_read += len(chunk)
                                total_read += len(chunk)
                                if member_read > limits.max_member_bytes:
                                    raise AndroidNativePatchError(
                                        f"APK member exceeds read limit: {info.filename}"
                                    )
                                if total_read > limits.max_total_uncompressed_bytes:
                                    raise AndroidNativePatchError(
                                        "APK uncompressed bytes exceed total read limit"
                                    )
                                digest.update(chunk)
                                if output_handle is not None:
                                    output_handle.write(chunk)
                    if member_read != int(info.file_size):
                        raise AndroidNativePatchError(
                            f"APK member size differs from ZIP metadata: {info.filename}"
                        )
                finally:
                    if output_handle is not None:
                        output_handle.close()
                entries.append(_entry_snapshot(info, digest.hexdigest()))
            comment = bytes(archive.comment)
    except Exception:
        _remove_file(extract_to)
        raise
    if not target_seen or not extract_to.is_file():
        raise AndroidNativePatchError(f"requested native library was not extracted: {member_name}")
    final_sha256 = _sha256_file(path, max_bytes=limits.max_archive_bytes)
    if final_sha256 != initial_sha256:
        _remove_file(extract_to)
        raise AndroidNativePatchError("APK changed while archive members were being read")
    signature_entries = [entry["name"] for entry in entries if _is_signature_entry(entry["name"])]
    signing_block = _has_apk_signing_block(path)
    return {
        "path": str(path),
        "sha256": final_sha256,
        "size": file_size,
        "entry_count": len(entries),
        "entries": entries,
        "comment_sha256": _sha256_bytes(comment),
        "comment_size": len(comment),
        "signature": {
            "v1_entries": signature_entries,
            "v1_present": bool(signature_entries),
            "apk_signing_block_present": signing_block,
            "material_present": bool(signature_entries or signing_block),
        },
        "limits": asdict(limits),
    }


def _validate_zip_catalog(
    infos: Sequence[zipfile.ZipInfo],
    *,
    limits: ApkPatchLimits,
) -> None:
    if len(infos) > limits.max_entries:
        raise AndroidNativePatchError(
            f"APK ZIP entry count exceeds limit {limits.max_entries}"
        )
    names: set[str] = set()
    total = 0
    for info in infos:
        issue = _zip_member_issue(info, limits=limits)
        if issue:
            raise AndroidNativePatchError(f"unsafe APK ZIP entry {info.filename!r}: {issue}")
        if info.filename in names:
            raise AndroidNativePatchError(f"APK contains duplicate ZIP entry: {info.filename}")
        names.add(info.filename)
        total += int(info.file_size)
        if total > limits.max_total_uncompressed_bytes:
            raise AndroidNativePatchError(
                "APK declared uncompressed size exceeds total limit "
                f"{limits.max_total_uncompressed_bytes}"
            )


def _zip_member_issue(info: zipfile.ZipInfo, *, limits: ApkPatchLimits) -> str | None:
    name = info.filename
    raw_name = str(getattr(info, "orig_filename", name))
    if raw_name != name:
        return "raw member path contains non-canonical separators or NUL bytes"
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = normalized.rstrip("/").split("/")
    if (
        not normalized
        or not path.parts
        or "\x00" in normalized
        or normalized.startswith("/")
        or "\\" in name
        or ".." in path.parts
        or any(part in {"", ".", ".."} for part in parts)
        or (path.parts and ":" in path.parts[0])
    ):
        return "unsafe or non-canonical member path"
    unix_mode = (int(info.external_attr) >> 16) & 0xFFFF
    if unix_mode and stat.S_ISLNK(unix_mode):
        return "symbolic-link member"
    if int(info.flag_bits) & 0x1:
        return "encrypted member"
    if int(info.compress_type) not in _SUPPORTED_COMPRESSION:
        return f"unsupported compression method {info.compress_type}"
    if int(info.file_size) < 0 or int(info.compress_size) < 0:
        return "negative ZIP size metadata"
    if int(info.file_size) > limits.max_member_bytes:
        return f"declared member size exceeds limit {limits.max_member_bytes}"
    if not info.is_dir() and int(info.file_size) > 0:
        if int(info.compress_size) <= 0:
            return "non-empty member has no compressed payload"
        if int(info.file_size) / int(info.compress_size) > limits.max_compression_ratio:
            return f"compression ratio exceeds limit {limits.max_compression_ratio}"
    return None


def _write_zip_copy(
    source: Path,
    destination: Path,
    *,
    member_name: str,
    replacement_path: Path,
    limits: ApkPatchLimits,
    strip_signatures: bool,
) -> dict[str, Any]:
    if destination.exists():
        raise AndroidNativePatchError(f"APK output already exists: {destination}")
    source_size = source.stat().st_size
    if source_size > limits.max_archive_bytes:
        raise AndroidNativePatchError(
            f"APK size exceeds limit {limits.max_archive_bytes}: {source_size}"
        )
    source_sha256 = _sha256_file(source, max_bytes=limits.max_archive_bytes)
    replacement_size = replacement_path.stat().st_size
    destination.parent.mkdir(parents=True, exist_ok=True)
    stripped: list[str] = []
    copied = 0
    total_written = 0
    target_seen = False
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    if temporary.exists():
        raise AndroidNativePatchError(f"temporary APK output already exists: {temporary}")
    try:
        with zipfile.ZipFile(source, "r", allowZip64=True) as input_archive:
            infos = input_archive.infolist()
            _validate_zip_catalog(infos, limits=limits)
            with zipfile.ZipFile(
                temporary,
                "x",
                allowZip64=True,
                strict_timestamps=False,
            ) as output_archive:
                output_archive.comment = bytes(input_archive.comment)
                for info in infos:
                    if strip_signatures and _is_signature_entry(info.filename):
                        stripped.append(info.filename)
                        continue
                    clone = _clone_zip_info(info)
                    if info.filename == member_name:
                        if replacement_size != int(info.file_size):
                            raise AndroidNativePatchError(
                                "patched native library size changed; APK orchestration only accepts layout-preserving patches"
                            )
                        source_handle = replacement_path.open("rb")
                        target_seen = True
                    elif info.is_dir():
                        output_archive.writestr(clone, b"")
                        copied += 1
                        continue
                    else:
                        source_handle = input_archive.open(info, "r")
                    member_written = 0
                    try:
                        with output_archive.open(
                            clone,
                            "w",
                            force_zip64=int(info.file_size) >= zipfile.ZIP64_LIMIT,
                        ) as output_handle:
                            while True:
                                chunk = source_handle.read(limits.read_chunk_bytes)
                                if not chunk:
                                    break
                                member_written += len(chunk)
                                total_written += len(chunk)
                                if member_written > limits.max_member_bytes:
                                    raise AndroidNativePatchError(
                                        f"APK member exceeds copy limit: {info.filename}"
                                    )
                                if total_written > limits.max_total_uncompressed_bytes:
                                    raise AndroidNativePatchError(
                                        "APK copy exceeds total uncompressed byte limit"
                                    )
                                output_handle.write(chunk)
                    finally:
                        source_handle.close()
                    if member_written != int(info.file_size):
                        raise AndroidNativePatchError(
                            f"APK copy size differs from source metadata: {info.filename}"
                        )
                    copied += 1
        if not target_seen:
            raise AndroidNativePatchError(f"requested native library is missing: {member_name}")
        if _sha256_file(source, max_bytes=limits.max_archive_bytes) != source_sha256:
            raise AndroidNativePatchError("source APK changed while it was being repackaged")
        os.replace(temporary, destination)
    except Exception:
        _remove_file(temporary)
        _remove_file(destination)
        raise
    return {
        "strategy": "zip-copy",
        "status": "ok",
        "copied_entry_count": copied,
        "stripped_signature_entries": stripped,
        "target_replaced": member_name,
        "compression_metadata_preserved": True,
        "archive_comment_preserved": True,
        "source_sha256": source_sha256,
    }


def _clone_zip_info(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    clone = zipfile.ZipInfo(info.filename, date_time=info.date_time)
    clone.compress_type = info.compress_type
    clone.comment = bytes(info.comment)
    clone.extra = bytes(info.extra)
    clone.create_system = info.create_system
    clone.create_version = info.create_version
    clone.extract_version = info.extract_version
    clone.reserved = info.reserved
    clone.flag_bits = info.flag_bits & ~0x1
    clone.volume = info.volume
    clone.internal_attr = info.internal_attr
    clone.external_attr = info.external_attr
    if hasattr(info, "_compresslevel"):
        clone._compresslevel = info._compresslevel  # type: ignore[attr-defined]
    return clone


def _entry_snapshot(info: zipfile.ZipInfo, sha256: str) -> dict[str, Any]:
    metadata = {
        "compress_type": int(info.compress_type),
        "date_time": list(info.date_time),
        "comment_size": len(info.comment),
        "comment_sha256": _sha256_bytes(bytes(info.comment)),
        "extra_size": len(info.extra),
        "extra_sha256": _sha256_bytes(bytes(info.extra)),
        "create_system": int(info.create_system),
        "create_version": int(info.create_version),
        "extract_version": int(info.extract_version),
        "flag_bits": int(info.flag_bits) & ~0x8,
        "volume": int(info.volume),
        "internal_attr": int(info.internal_attr),
        "external_attr": int(info.external_attr),
    }
    return {
        "name": info.filename,
        "is_dir": info.is_dir(),
        "file_size": int(info.file_size),
        "compressed_size": int(info.compress_size),
        "crc32": f"{int(info.CRC) & 0xFFFFFFFF:08x}",
        "sha256": sha256,
        "metadata": metadata,
        "metadata_sha256": _canonical_sha256(metadata),
        "signature_entry": _is_signature_entry(info.filename),
    }


def _compare_application_entries(
    source: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    member_name: str,
    expected_member_sha256: str,
) -> dict[str, Any]:
    expected = [entry for entry in source["entries"] if not entry["signature_entry"]]
    observed = [entry for entry in candidate["entries"] if not entry["signature_entry"]]
    errors: list[str] = []
    expected_names = [entry["name"] for entry in expected]
    observed_names = [entry["name"] for entry in observed]
    if observed_names != expected_names:
        errors.append("non-signature APK entry names or order changed during repack")
    observed_by_name = {entry["name"]: entry for entry in observed}
    preserved_count = 0
    entry_evidence: list[dict[str, Any]] = []
    for entry in expected:
        actual = observed_by_name.get(entry["name"])
        if actual is None:
            continue
        is_target = entry["name"] == member_name
        expected_hash = expected_member_sha256 if entry["name"] == member_name else entry["sha256"]
        if actual["sha256"] != expected_hash:
            errors.append(f"APK entry content changed unexpectedly: {entry['name']}")
        elif not is_target:
            preserved_count += 1
        if actual["metadata_sha256"] != entry["metadata_sha256"]:
            errors.append(f"APK entry compression metadata changed: {entry['name']}")
        if actual["file_size"] != entry["file_size"]:
            errors.append(f"APK entry size changed: {entry['name']}")
        if not is_target and actual["compressed_size"] != entry["compressed_size"]:
            errors.append(f"APK entry compressed size changed: {entry['name']}")
        if not is_target and actual["crc32"] != entry["crc32"]:
            errors.append(f"APK entry CRC-32 changed: {entry['name']}")
        entry_evidence.append(
            {
                "name": entry["name"],
                "target": is_target,
                "source_crc32": entry["crc32"],
                "output_crc32": actual["crc32"],
                "source_file_size": entry["file_size"],
                "output_file_size": actual["file_size"],
                "source_compressed_size": entry["compressed_size"],
                "output_compressed_size": actual["compressed_size"],
                "compress_type": actual["metadata"]["compress_type"],
            }
        )
    if candidate["comment_sha256"] != source["comment_sha256"]:
        errors.append("APK archive comment changed during repack")
    return {
        "valid": not errors,
        "errors": errors,
        "source_entry_count": len(source["entries"]),
        "output_entry_count": len(candidate["entries"]),
        "preserved_application_entries": preserved_count,
        "target_member_sha256": expected_member_sha256,
        "stripped_signature_entries": [
            entry["name"] for entry in source["entries"] if entry["signature_entry"]
        ],
        "metadata_preserved": not any("metadata" in error for error in errors),
        "crc_size_compression_evidence": entry_evidence,
        "unchanged_entry_crc_and_compressed_size_preserved": not any(
            "CRC-32" in error or "compressed size" in error for error in errors
        ),
        "archive_comment_preserved": candidate["comment_sha256"] == source["comment_sha256"],
    }


def _expected_application_entries(
    source: Mapping[str, Any],
    unsigned: Mapping[str, Any],
    *,
    member_name: str,
) -> list[dict[str, Any]]:
    source_by_name = {entry["name"]: entry for entry in source["entries"]}
    result: list[dict[str, Any]] = []
    for entry in unsigned["entries"]:
        if entry["signature_entry"]:
            continue
        expected = dict(entry)
        if entry["name"] != member_name:
            expected["source_sha256"] = source_by_name[entry["name"]]["sha256"]
        result.append(expected)
    return result


def _compare_expected_entries(
    expected: Sequence[Mapping[str, Any]],
    observed_scan: Mapping[str, Any],
    *,
    comment_sha256: str,
) -> dict[str, Any]:
    observed = [entry for entry in observed_scan["entries"] if not entry["signature_entry"]]
    errors: list[str] = []
    expected_names = [str(entry.get("name") or "") for entry in expected]
    observed_names = [entry["name"] for entry in observed]
    if expected_names != observed_names:
        errors.append("application APK entry names or order do not match the patch plan")
    observed_by_name = {entry["name"]: entry for entry in observed}
    checked_fields = (
        "sha256",
        "metadata_sha256",
        "file_size",
        "compressed_size",
        "crc32",
        "is_dir",
    )
    for entry in expected:
        name = str(entry.get("name") or "")
        actual = observed_by_name.get(name)
        if actual is None:
            continue
        for field in checked_fields:
            if actual[field] != entry.get(field):
                label = {
                    "sha256": "SHA-256",
                    "metadata_sha256": "metadata",
                    "file_size": "file size",
                    "compressed_size": "compressed size",
                    "crc32": "CRC-32",
                    "is_dir": "directory type",
                }[field]
                errors.append(f"APK entry {label} does not match plan: {name}")
    if observed_scan["comment_sha256"] != comment_sha256:
        errors.append("APK archive comment does not match plan")
    return {
        "valid": not errors,
        "errors": errors,
        "expected_entry_count": len(expected),
        "observed_application_entry_count": len(observed),
        "checked_fields": list(checked_fields),
        "crc_size_compression_verified": not errors,
    }


def _elf_baseline(path: Path, abi: str) -> dict[str, Any]:
    image = parse_android_elf(path)
    expected = _ABI_EXPECTATIONS[abi]
    mismatches: list[str] = []
    for field in ("machine", "bits", "architecture"):
        observed = getattr(image, field)
        if observed != expected[field]:
            mismatches.append(
                f"ELF {field} {observed!r} does not match ABI {abi} ({expected[field]!r})"
            )
    if mismatches:
        raise AndroidNativePatchError("; ".join(mismatches))

    # Reuse the bounded Android analyzer for dynamic/JNI symbol evidence.
    from .android import _analyze_elf

    data = path.read_bytes()
    symbol_analysis = _analyze_elf(data, abi, len(data), False)
    if not symbol_analysis.get("present"):
        raise AndroidNativePatchError("Android ELF symbol baseline could not parse the library")
    if symbol_analysis.get("abi_consistent") is False:
        raise AndroidNativePatchError("ELF machine conflicts with the requested APK ABI directory")
    relocation_digest = hashlib.sha256()
    examples: list[dict[str, Any]] = []
    for relocation in image.relocations:
        serialized = relocation.to_dict()
        relocation_digest.update(_canonical_json(serialized).encode("utf-8"))
        relocation_digest.update(b"\n")
        if len(examples) < _MAX_RELOCATION_EXAMPLES:
            examples.append(serialized)
    section_digest = hashlib.sha256()
    section_examples: list[dict[str, Any]] = []
    for section in image.sections:
        serialized_section = _section_snapshot(section)
        section_digest.update(_canonical_json(serialized_section).encode("utf-8"))
        section_digest.update(b"\n")
        if len(section_examples) < _MAX_SECTION_EXAMPLES:
            section_examples.append(serialized_section)
    load_segments = [segment.to_dict() for segment in image.load_segments]
    jni_exports = sorted({str(item) for item in symbol_analysis.get("jni_exports") or []})
    return {
        "sha256": _sha256_bytes(data),
        "size": len(data),
        "abi": abi,
        "machine": image.machine,
        "machine_name": symbol_analysis.get("machine_name"),
        "bits": image.bits,
        "architecture": image.architecture,
        "elf_type": image.elf_type,
        "entrypoint": image.entrypoint,
        "image_base": min(segment.virtual_address for segment in image.load_segments),
        "endianness": symbol_analysis.get("endianness"),
        "abi_consistent": True,
        "load_segment_count": len(load_segments),
        "load_segments": load_segments,
        "load_segments_sha256": _canonical_sha256(load_segments),
        "section_count": len(image.sections),
        "sections_sha256": section_digest.hexdigest(),
        "sections": section_examples,
        "sections_truncated": len(image.sections) > len(section_examples),
        "jni_exports": jni_exports,
        "jni_export_count": len(jni_exports),
        "jni_symbol_source": symbol_analysis.get("symbol_source"),
        "relocation_count": len(image.relocations),
        "relocations_sha256": relocation_digest.hexdigest(),
        "relocation_coverage": image.relocation_coverage,
        "relocation_notes": list(image.relocation_notes),
        "relocations": examples,
        "relocations_truncated": len(image.relocations) > len(examples),
    }


def _elf_invariants(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    require_change: bool,
) -> dict[str, Any]:
    errors: list[str] = []
    stable_fields = (
        "size",
        "abi",
        "machine",
        "bits",
        "architecture",
        "elf_type",
        "entrypoint",
        "image_base",
        "endianness",
        "load_segment_count",
        "load_segments_sha256",
        "section_count",
        "sections_sha256",
        "jni_exports",
        "jni_export_count",
        "relocation_count",
        "relocations_sha256",
        "relocation_coverage",
    )
    for field in stable_fields:
        if before.get(field) != after.get(field):
            errors.append(f"ELF baseline changed unexpectedly: {field}")
    if require_change and before.get("sha256") == after.get("sha256"):
        errors.append("ELF patch produced no byte change")
    return {
        "valid": not errors,
        "errors": errors,
        "machine_abi_preserved": all(
            before.get(field) == after.get(field)
            for field in ("abi", "machine", "bits", "architecture")
        ),
        "jni_exports_preserved": before.get("jni_exports") == after.get("jni_exports"),
        "relocations_preserved": all(
            before.get(field) == after.get(field)
            for field in ("relocation_count", "relocations_sha256", "relocation_coverage")
        ),
        "layout_preserved": before.get("size") == after.get("size"),
        "bytes_changed": before.get("sha256") != after.get("sha256"),
    }


def _expected_elf_matches(
    expected: Mapping[str, Any],
    observed: Mapping[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    fields = (
        "sha256",
        "size",
        "abi",
        "machine",
        "bits",
        "architecture",
        "entrypoint",
        "image_base",
        "load_segment_count",
        "load_segments_sha256",
        "section_count",
        "sections_sha256",
        "jni_exports",
        "jni_export_count",
        "relocation_count",
        "relocations_sha256",
        "relocation_coverage",
    )
    for field in fields:
        if expected.get(field) != observed.get(field):
            errors.append(f"patched ELF does not match planned baseline: {field}")
    return {"valid": not errors, "errors": errors}


def _complete_signing(
    unsigned_apk: Path,
    *,
    artifact_root: Path,
    requested: bool,
    signing: Mapping[str, Any] | None,
    apksigner_path: str | None,
    timeout: float,
    before: Mapping[str, Any],
    unsigned: Mapping[str, Any],
) -> tuple[dict[str, Any], Path]:
    base = {
        "requested": requested,
        "before": dict(before),
        "unsigned": dict(unsigned),
        "signed": False,
        "dependency_gated": False,
        "install_ready": False,
    }
    if not requested:
        if apksigner_path is None:
            base.update(
                {
                    "status": "dependency-gated",
                    "dependency_gated": True,
                    "gate": "apksigner",
                    "reason": "apksigner is unavailable; the patched artifact is unsigned",
                    "after": dict(unsigned),
                }
            )
        else:
            base.update(
                {
                    "status": "unsigned-not-requested",
                    "reason": "signing was not requested",
                    "after": dict(unsigned),
                }
            )
        return base, unsigned_apk
    if apksigner_path is None:
        base.update(
            {
                "status": "dependency-gated",
                "dependency_gated": True,
                "gate": "apksigner",
                "reason": "apksigner is unavailable; unsigned patched APK was retained",
                "after": dict(unsigned),
            }
        )
        return base, unsigned_apk
    config, errors = _normalize_signing(signing)
    if errors:
        base.update(
            {
                "status": "dependency-gated",
                "dependency_gated": True,
                "gate": "signing-configuration",
                "reason": "; ".join(errors),
                "after": dict(unsigned),
            }
        )
        return base, unsigned_apk

    signed_path = artifact_root / "signed-patched.apk"
    sign_result = _run_apksigner_sign(
        apksigner_path,
        unsigned_apk=unsigned_apk,
        signed_apk=signed_path,
        config=config,
        timeout=timeout,
    )
    if not sign_result["succeeded"]:
        raise AndroidNativePatchError(
            f"apksigner sign failed: {sign_result.get('error') or sign_result.get('stderr') or 'unknown error'}"
        )
    static = _static_signature_snapshot(signed_path)
    verification = _run_apksigner_verify(apksigner_path, signed_path, timeout=timeout)
    if not static["material_present"] or not verification["verified"]:
        raise AndroidNativePatchError(
            "apksigner output was not accepted as signed: signature material and successful verify are both required"
        )
    after = {**static, "verification": verification, "state": "verified-signed"}
    base.update(
        {
            "status": "verified-signed",
            "signed": True,
            "install_ready": True,
            "after": after,
            "sign_command": sign_result,
        }
    )
    return base, signed_path


def _signature_with_verification(
    static: Mapping[str, Any],
    path: Path,
    apksigner_path: str | None,
    *,
    timeout: float,
) -> dict[str, Any]:
    if apksigner_path is None:
        verification = {
            "status": "dependency-gated",
            "verified": False,
            "dependency": "apksigner",
            "reason": "apksigner is unavailable",
        }
    else:
        verification = _run_apksigner_verify(apksigner_path, path, timeout=timeout)
    if verification.get("verified") and static.get("material_present"):
        state = "verified-signed"
    elif static.get("material_present"):
        state = "signature-material-unverified"
    else:
        state = "unsigned"
    return {**dict(static), "state": state, "verification": verification}


def _verify_expected_signing(
    path: Path,
    static: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    apksigner_path: str | None,
    timeout: float,
) -> dict[str, Any]:
    errors: list[str] = []
    expected_signed = bool(expected.get("signed"))
    evidence = _signature_with_verification(static, path, apksigner_path, timeout=timeout)
    if expected_signed:
        if not static.get("material_present"):
            errors.append("plan expects a signed APK but signature material is absent")
        if apksigner_path is not None and not evidence["verification"].get("verified"):
            errors.append("apksigner did not verify the APK expected to be signed")
    elif static.get("material_present"):
        errors.append("plan expects an unsigned APK but signature material is present")
    dependency_gated = expected_signed and apksigner_path is None and not errors
    return {
        "valid": not errors,
        "errors": errors,
        "expected_signed": expected_signed,
        "observed": evidence,
        "dependency_gated": dependency_gated,
        "check_status": "dependency-gated" if dependency_gated else None,
    }


def _normalize_signing(
    signing: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], list[str]]:
    values = dict(signing or {})
    keystore = _first(values, "keystore", "keystore_path", "ks")
    key_path = _first(values, "key", "key_path", "private_key")
    cert_path = _first(values, "cert", "cert_path", "certificate")
    alias = _first(values, "key_alias", "ks_key_alias", "alias")
    ks_pass = _first(values, "ks_pass", "keystore_password")
    key_pass = _first(values, "key_pass", "key_password")
    raw_args = values.get("apksigner_args", values.get("args", [])) or []
    if isinstance(raw_args, str):
        extra_args = [raw_args]
    elif isinstance(raw_args, Sequence):
        extra_args = [str(item) for item in raw_args]
    else:
        return {}, ["signing apksigner_args must be a string or sequence"]
    errors: list[str] = []
    if any(item == "--out" or item.startswith("--out=") for item in extra_args):
        errors.append("signing apksigner_args cannot override --out")
    if keystore:
        keystore_path = Path(str(keystore)).expanduser().resolve()
        if not keystore_path.is_file():
            errors.append("apksigner keystore does not exist")
        mode = "keystore"
    elif key_path or cert_path:
        key = Path(str(key_path or "")).expanduser().resolve()
        cert = Path(str(cert_path or "")).expanduser().resolve()
        if not key.is_file() or not cert.is_file():
            errors.append("apksigner key and certificate files are both required")
        mode = "key-cert"
    elif extra_args:
        mode = "arguments"
    else:
        errors.append("signing requested without apksigner credentials or arguments")
        mode = "unconfigured"
    return (
        {
            "mode": mode,
            "keystore": str(Path(str(keystore)).expanduser().resolve()) if keystore else None,
            "key_path": str(Path(str(key_path)).expanduser().resolve()) if key_path else None,
            "cert_path": str(Path(str(cert_path)).expanduser().resolve()) if cert_path else None,
            "key_alias": str(alias) if alias else None,
            "ks_pass": str(ks_pass) if ks_pass is not None else None,
            "key_pass": str(key_pass) if key_pass is not None else None,
            "extra_args": extra_args,
        },
        errors,
    )


def _run_apksigner_sign(
    executable: str,
    *,
    unsigned_apk: Path,
    signed_apk: Path,
    config: Mapping[str, Any],
    timeout: float,
) -> dict[str, Any]:
    command = [executable, "sign", "--out", str(signed_apk)]
    mode = config.get("mode")
    if mode == "keystore":
        command.extend(["--ks", str(config["keystore"])])
        if config.get("key_alias"):
            command.extend(["--ks-key-alias", str(config["key_alias"])])
        if config.get("ks_pass") is not None:
            command.extend(["--ks-pass", _password_argument(config["ks_pass"])])
        if config.get("key_pass") is not None:
            command.extend(["--key-pass", _password_argument(config["key_pass"])])
    elif mode == "key-cert":
        command.extend(
            ["--key", str(config["key_path"]), "--cert", str(config["cert_path"])]
        )
        if config.get("key_pass") is not None:
            command.extend(["--key-pass", _password_argument(config["key_pass"])])
    command.extend(str(item) for item in config.get("extra_args") or [])
    command.append(str(unsigned_apk))
    result = _run_process(command, timeout=timeout)
    succeeded = result["returncode"] == 0 and signed_apk.is_file()
    if result["returncode"] == 0 and not signed_apk.is_file():
        result["error"] = "apksigner reported success without producing an output APK"
    result["succeeded"] = succeeded
    result["command"] = _redact_command(command)
    return result


def _run_apksigner_verify(
    executable: str,
    path: Path,
    *,
    timeout: float,
) -> dict[str, Any]:
    command = [executable, "verify", "--verbose", "--print-certs", str(path)]
    result = _run_process(command, timeout=timeout)
    result["verified"] = result["returncode"] == 0
    result["status"] = "verified" if result["verified"] else "not-verified"
    result["command"] = command
    return result


def _run_process(command: Sequence[str], *, timeout: float) -> dict[str, Any]:
    if timeout <= 0 or timeout > 3_600:
        raise AndroidNativePatchError("signing_timeout must be in the range (0, 3600]")
    try:
        completed = subprocess.run(
            [str(item) for item in command],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return {
            "returncode": int(completed.returncode),
            "stdout": (completed.stdout or "")[-_MAX_PROCESS_OUTPUT:],
            "stderr": (completed.stderr or "")[-_MAX_PROCESS_OUTPUT:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": -1,
            "stdout": _process_text(exc.stdout),
            "stderr": _process_text(exc.stderr),
            "error": f"apksigner timed out after {timeout} seconds",
        }
    except OSError as exc:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "error": f"{type(exc).__name__}: {exc}",
        }


def _static_signature_snapshot(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path, "r") as archive:
        entries = [info.filename for info in archive.infolist() if _is_signature_entry(info.filename)]
    signing_block = _has_apk_signing_block(path)
    return {
        "v1_entries": entries,
        "v1_present": bool(entries),
        "apk_signing_block_present": signing_block,
        "material_present": bool(entries or signing_block),
    }


def _has_apk_signing_block(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            central_offset = int(archive.start_dir)
        if central_offset < 24:
            return False
        with path.open("rb") as handle:
            handle.seek(central_offset - 24)
            footer = handle.read(24)
            if len(footer) != 24 or footer[8:] != _APK_SIGNATURE_MAGIC:
                return False
            block_size = int.from_bytes(footer[:8], "little")
            block_start = central_offset - block_size - 8
            if block_size < 24 or block_start < 0:
                return False
            handle.seek(block_start)
            return int.from_bytes(handle.read(8), "little") == block_size
    except (OSError, ValueError, zipfile.BadZipFile):
        return False


def _is_signature_entry(name: str) -> bool:
    path = PurePosixPath(name)
    if len(path.parts) != 2 or path.parts[0].upper() != "META-INF":
        return False
    filename = path.parts[1].upper()
    return filename == "MANIFEST.MF" or filename.endswith(_SIGNATURE_SUFFIXES)


def _apk_plan_payload(
    *,
    source: Path,
    destination: Path,
    member_name: str,
    abi: str,
    source_scan: Mapping[str, Any],
    final_scan: Mapping[str, Any],
    expected_entries: Sequence[Mapping[str, Any]],
    before_elf: Mapping[str, Any],
    after_elf: Mapping[str, Any],
    elf_invariants: Mapping[str, Any],
    signing: Mapping[str, Any],
    toolchain: Mapping[str, Any],
    limits: ApkPatchLimits,
    elf_plan_path: Path,
    generic_rollback_path: Path,
    elf_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": _PLAN_NAME,
        "source": {
            "path": str(source),
            "sha256": source_scan["sha256"],
            "size": source_scan["size"],
        },
        "output": {
            "path": str(destination),
            "sha256": final_scan["sha256"],
            "size": final_scan["size"],
        },
        "target": {
            "abi": abi,
            "library_path": member_name,
            "source_entry": next(
                dict(entry)
                for entry in source_scan["entries"]
                if entry["name"] == member_name
            ),
        },
        "archive": {
            "source_entry_count": source_scan["entry_count"],
            "expected_application_entries": [dict(item) for item in expected_entries],
            "comment_sha256": source_scan["comment_sha256"],
            "stripped_signature_entries": [
                entry["name"] for entry in source_scan["entries"] if entry["signature_entry"]
            ],
        },
        "elf": {
            "before": dict(before_elf),
            "after": dict(after_elf),
            "invariants": dict(elf_invariants),
            "plan_path": str(elf_plan_path),
            "plan_sha256": _sha256_file(elf_plan_path),
            "evidence": dict(elf_evidence),
        },
        "rollback": {
            "path": str(generic_rollback_path),
            "sha256": _sha256_file(generic_rollback_path),
        },
        "signing": dict(signing),
        "toolchain": dict(toolchain),
        "limits": asdict(limits),
        "provenance": {
            "source_apk_sha256": source_scan["sha256"],
            "output_apk_sha256": final_scan["sha256"],
            "selected_member": member_name,
            "selected_abi": abi,
            "address_mapping": dict(elf_evidence["address_mapping"]),
            "caller_expected_bytes_verified": bool(
                elf_evidence["address_mapping"].get("preimage_verified")
            ),
            "elf_artifacts": [
                *elf_evidence["planner"]["artifacts"],
                *elf_evidence["independent_verification"]["artifacts"],
            ],
        },
    }


def _apk_rollback_payload(
    *,
    source: Path,
    destination: Path,
    member_name: str,
    abi: str,
    source_scan: Mapping[str, Any],
    final_scan: Mapping[str, Any],
    before_elf: Mapping[str, Any],
    after_elf: Mapping[str, Any],
    generic_rollback: Mapping[str, Any],
    generic_rollback_path: Path,
    signing: Mapping[str, Any],
    limits: ApkPatchLimits,
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": "android_native_apk_rollback",
        "source_apk": {
            "path": str(source),
            "sha256": source_scan["sha256"],
            "size": source_scan["size"],
        },
        "patched_apk": {
            "path": str(destination),
            "sha256": final_scan["sha256"],
            "size": final_scan["size"],
        },
        "target": {"abi": abi, "library_path": member_name},
        "elf": {
            "source_sha256": before_elf["sha256"],
            "patched_sha256": after_elf["sha256"],
            "source_size": before_elf["size"],
            "patched_size": after_elf["size"],
        },
        "generic_elf_rollback": dict(generic_rollback),
        "generic_elf_rollback_artifact": {
            "path": str(generic_rollback_path),
            "sha256": _sha256_file(generic_rollback_path),
        },
        "source_signing": dict(signing.get("before") or {}),
        "patched_signing": dict(signing.get("after") or {}),
        "limits": asdict(limits),
    }


def _initial_verify_payload(
    *,
    source: Path,
    destination: Path,
    member_name: str,
    source_sha256: str,
    final_scan: Mapping[str, Any],
    archive_check: Mapping[str, Any],
    elf_check: Mapping[str, Any],
    rollback_proof_sha256: str,
    expected_restored_sha256: str,
    signing: Mapping[str, Any],
    completion_status: str,
) -> dict[str, Any]:
    rollback_ok = rollback_proof_sha256 == expected_restored_sha256
    source_ok = _sha256_file(source) == source_sha256
    valid = bool(archive_check["valid"] and elf_check["valid"] and rollback_ok and source_ok)
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": "android_native_apk_patch_verify",
        "status": "ok" if valid else "failed",
        "completion_status": completion_status,
        "valid": valid,
        "source": {"path": str(source), "sha256": source_sha256, "unchanged": source_ok},
        "output": {
            "path": str(destination),
            "sha256": final_scan["sha256"],
            "size": final_scan["size"],
        },
        "target": {"library_path": member_name},
        "checks": [
            _check("source_apk_unchanged", source_ok),
            _check("archive_content_and_metadata", bool(archive_check["valid"]), archive_check),
            _check("elf_machine_abi_jni_relocations", bool(elf_check["valid"]), elf_check),
            _check("generic_rollback_proof", rollback_ok),
            _check(
                "signing",
                bool(signing.get("signed")) or not bool(signing.get("requested")),
                signing,
                status=(
                    "dependency-gated"
                    if signing.get("status") == "dependency-gated"
                    else None
                ),
            ),
        ],
        "errors": [],
        "archive": dict(archive_check),
        "elf": dict(elf_check),
        "signing": dict(signing),
    }


def _patch_artifacts(
    *,
    destination: Path,
    unsigned_apk: Path,
    plan_path: Path,
    verify_path: Path,
    rollback_path: Path,
    elf_plan_path: Path,
    generic_rollback_path: Path,
    signed: bool,
    evidence_paths: Sequence[tuple[Path, str]],
) -> list[dict[str, Any]]:
    primary = [
        _artifact(destination, "signed-patched-apk" if signed else "unsigned-patched-apk"),
        _artifact(unsigned_apk, "unsigned-patched-apk"),
        _artifact(plan_path, "android-native-patch-plan"),
        _artifact(verify_path, "android-native-patch-verify"),
        _artifact(rollback_path, "android-native-apk-rollback"),
        _artifact(elf_plan_path, "android-elf-patch-plan"),
        _artifact(generic_rollback_path, "binary-patch-rollback"),
    ]
    seen = {str(Path(item["path"]).resolve()) for item in primary}
    for path, kind in evidence_paths:
        resolved = str(path.resolve())
        if resolved in seen:
            continue
        if not path.is_file():
            raise AndroidNativePatchError(f"required patch evidence artifact is missing: {path}")
        primary.append(_artifact(path, kind))
        seen.add(resolved)
    return primary


def _elf_artifact_paths(
    artifact_root: Path,
    *,
    extracted_path: Path,
    patched_so: Path,
    rollback_proof_so: Path,
) -> list[tuple[Path, str]]:
    return [
        (extracted_path, "extracted-source-elf"),
        (patched_so, "patched-elf"),
        (artifact_root / "elf-plan" / "plan.json", "android-elf-patch-plan"),
        (artifact_root / "elf-plan" / "verify.json", "android-elf-patch-verification"),
        (artifact_root / "elf-plan" / "risk_report.json", "android-elf-patch-risk-report"),
        (artifact_root / "elf-plan" / "rollback_plan.json", "android-elf-patch-rollback-plan"),
        (artifact_root / "elf-verify" / "verify.json", "android-elf-independent-verification"),
        (artifact_root / "elf-verify" / "risk_report.json", "android-elf-independent-risk-report"),
        (artifact_root / "elf-verify" / "rollback_plan.json", "android-elf-independent-rollback-plan"),
        (artifact_root / "elf-apply" / "patch_manifest.json", "binary-patch-manifest"),
        (artifact_root / "elf-apply" / "rollback.json", "binary-patch-rollback"),
        (rollback_proof_so, "elf-rollback-proof"),
        (
            artifact_root / "elf-rollback-proof" / "artifacts" / "rollback_manifest.json",
            "elf-rollback-proof-manifest",
        ),
    ]


def _verify_source_identity(plan: Mapping[str, Any]) -> dict[str, Any]:
    source = _mapping(plan.get("source"), "plan.source")
    path = Path(str(source.get("path") or "")).expanduser().resolve()
    expected = _required_sha256(source.get("sha256"), "plan.source.sha256")
    if not path.is_file():
        return {
            "valid": True,
            "available": False,
            "errors": [],
            "status": "not-available",
            "path": str(path),
        }
    observed = _sha256_file(path)
    valid = observed == expected
    return {
        "valid": valid,
        "available": True,
        "errors": [] if valid else ["source APK no longer matches its planned SHA-256"],
        "status": "unchanged" if valid else "changed",
        "path": str(path),
        "expected_sha256": expected,
        "observed_sha256": observed,
    }


def _validate_apk_plan(plan: Mapping[str, Any]) -> None:
    if plan.get("schema_version") != _SCHEMA_VERSION or plan.get("kind") != _PLAN_NAME:
        raise AndroidNativePatchError("unsupported APK native patch plan schema or kind")
    source = _mapping(plan.get("source"), "plan.source")
    output = _mapping(plan.get("output"), "plan.output")
    target = _mapping(plan.get("target"), "plan.target")
    archive = _mapping(plan.get("archive"), "plan.archive")
    elf = _mapping(plan.get("elf"), "plan.elf")
    _required_text(source.get("path"), "plan.source.path")
    _required_sha256(source.get("sha256"), "plan.source.sha256")
    _required_sha256(output.get("sha256"), "plan.output.sha256")
    abi = _normalize_abi(_required_text(target.get("abi"), "plan.target.abi"))
    _canonical_planned_member(
        abi,
        target.get("library_path"),
        "plan.target.library_path",
    )
    _required_sha256(archive.get("comment_sha256"), "plan.archive.comment_sha256")
    expected_entries = _sequence_of_mappings(
        archive.get("expected_application_entries"),
        "plan.archive.expected_application_entries",
    )
    _validate_expected_entries(expected_entries)
    after = _mapping(elf.get("after"), "plan.elf.after")
    _required_sha256(after.get("sha256"), "plan.elf.after.sha256")


def _validate_expected_entries(entries: Sequence[Mapping[str, Any]]) -> None:
    names: set[str] = set()
    for index, entry in enumerate(entries):
        label = f"plan.archive.expected_application_entries[{index}]"
        name = _required_text(entry.get("name"), f"{label}.name")
        if name in names:
            raise AndroidNativePatchError(f"{label}.name is duplicated")
        names.add(name)
        _required_sha256(entry.get("sha256"), f"{label}.sha256")
        _required_sha256(entry.get("metadata_sha256"), f"{label}.metadata_sha256")
        for field in ("file_size", "compressed_size"):
            _nonnegative_value(entry.get(field), field=f"{label}.{field}")
        crc32 = str(entry.get("crc32") or "").casefold()
        if len(crc32) != 8 or any(character not in "0123456789abcdef" for character in crc32):
            raise AndroidNativePatchError(f"{label}.crc32 must be an 8-digit hexadecimal CRC-32")
        if not isinstance(entry.get("is_dir"), bool):
            raise AndroidNativePatchError(f"{label}.is_dir must be boolean")


def _validate_apk_rollback(payload: Mapping[str, Any]) -> None:
    if (
        payload.get("schema_version") != _SCHEMA_VERSION
        or payload.get("kind") != "android_native_apk_rollback"
    ):
        raise AndroidNativePatchError("unsupported APK native rollback schema or kind")
    source = _mapping(payload.get("source_apk"), "rollback.source_apk")
    patched = _mapping(payload.get("patched_apk"), "rollback.patched_apk")
    target = _mapping(payload.get("target"), "rollback.target")
    elf = _mapping(payload.get("elf"), "rollback.elf")
    _mapping(payload.get("generic_elf_rollback"), "rollback.generic_elf_rollback")
    _required_text(source.get("path"), "rollback.source_apk.path")
    _required_sha256(source.get("sha256"), "rollback.source_apk.sha256")
    _required_sha256(patched.get("sha256"), "rollback.patched_apk.sha256")
    abi = _normalize_abi(_required_text(target.get("abi"), "rollback.target.abi"))
    _canonical_planned_member(
        abi,
        target.get("library_path"),
        "rollback.target.library_path",
    )
    _required_sha256(elf.get("source_sha256"), "rollback.elf.source_sha256")
    _required_sha256(elf.get("patched_sha256"), "rollback.elf.patched_sha256")


def _native_member_path(abi: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AndroidNativePatchError("library_path must be a non-empty string")
    raw = value.strip()
    if "\\" in raw or "\x00" in raw:
        raise AndroidNativePatchError("library_path must use a canonical APK POSIX path")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or any(part in {"", "."} for part in path.parts):
        raise AndroidNativePatchError("library_path contains an unsafe path component")
    if len(path.parts) == 1:
        path = PurePosixPath("lib", abi, path.name)
    if len(path.parts) != 3 or path.parts[:2] != ("lib", abi):
        raise AndroidNativePatchError(
            f"library_path must resolve exactly under lib/{abi}/"
        )
    if not path.name.startswith("lib") or not path.name.endswith(".so"):
        raise AndroidNativePatchError("library_path must name an Android lib*.so member")
    return path.as_posix()


def _canonical_planned_member(abi: str, value: Any, label: str) -> str:
    raw = _required_text(value, label)
    canonical = _native_member_path(abi, raw)
    if raw != canonical:
        raise AndroidNativePatchError(f"{label} must be the canonical full APK member path")
    return canonical


def _one_library_argument(*values: str | None) -> str:
    provided = [value for value in values if value not in (None, "")]
    if len(provided) != 1:
        raise AndroidNativePatchError(
            "provide exactly one of library_path, library, or lib_path"
        )
    return str(provided[0])


def _normalize_abi(value: str) -> str:
    normalized = str(value or "").strip().casefold()
    if normalized not in _ABI_EXPECTATIONS:
        supported = ", ".join(sorted(_ABI_EXPECTATIONS))
        raise AndroidNativePatchError(
            f"unsupported native patch ABI {value!r}; supported ABIs: {supported}"
        )
    return normalized


def _coerce_limits(value: ApkPatchLimits | Mapping[str, Any] | None) -> ApkPatchLimits:
    if value is None:
        return DEFAULT_APK_PATCH_LIMITS
    if isinstance(value, ApkPatchLimits):
        result = value
    elif isinstance(value, Mapping):
        allowed = set(ApkPatchLimits.__dataclass_fields__)
        unknown = sorted(str(key) for key in value if key not in allowed)
        if unknown:
            raise AndroidNativePatchError(
                f"unknown APK patch limit fields: {', '.join(unknown)}"
            )
        invalid = [
            str(key)
            for key, item in value.items()
            if not isinstance(item, int) or isinstance(item, bool) or item <= 0
        ]
        if invalid:
            raise AndroidNativePatchError(
                "APK patch limits must be positive integers: " + ", ".join(sorted(invalid))
            )
        result = ApkPatchLimits(**{str(key): item for key, item in value.items()})
    else:
        raise AndroidNativePatchError("limits must be ApkPatchLimits or a mapping")
    for field, item in asdict(result).items():
        if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
            raise AndroidNativePatchError(f"APK patch limit {field} must be a positive integer")
    return result


def _toolchain_state(
    *,
    apksigner_path: str | None,
    apktool_path: str | None,
) -> dict[str, Any]:
    return {
        "strategy": "zip-copy",
        "apktool": {
            "required": False,
            "available": apktool_path is not None,
            "path": apktool_path,
            "status": "available-not-required" if apktool_path else "unavailable-not-required",
        },
        "apksigner": {
            "required_for_signed_output": True,
            "available": apksigner_path is not None,
            "path": apksigner_path,
            "status": "available" if apksigner_path else "dependency-gated",
        },
    }


def _resolve_executable(value: str | Path | None, default: str) -> str | None:
    if value is None:
        return shutil.which(default)
    text = str(value).strip()
    if not text:
        return None
    candidate = Path(text).expanduser()
    if candidate.is_file():
        return str(candidate.resolve())
    return shutil.which(text)


def _require_tool_ok(result: ToolResult, label: str) -> None:
    if result.status != "ok":
        detail = result.error or _canonical_json(result.data)
        raise AndroidNativePatchError(f"{label} failed: {detail}")


def _artifact_root(
    source: Path,
    *,
    artifact_dir: str | Path | None,
    out_dir: str | Path | None,
) -> Path:
    if artifact_dir is not None and out_dir is not None:
        left = Path(artifact_dir).expanduser().resolve()
        right = Path(out_dir).expanduser().resolve()
        if left != right:
            raise AndroidNativePatchError("artifact_dir and out_dir identify different paths")
    value = artifact_dir if artifact_dir is not None else out_dir
    return (
        Path(value).expanduser().resolve()
        if value is not None
        else source.with_name(f"{source.stem}.native-patch-artifacts")
    )


def _rollback_artifact_root(
    source: Path,
    *,
    artifact_dir: str | Path | None,
    out_dir: str | Path | None,
) -> Path:
    if artifact_dir is not None and out_dir is not None:
        left = Path(artifact_dir).expanduser().resolve()
        right = Path(out_dir).expanduser().resolve()
        if left != right:
            raise AndroidNativePatchError("artifact_dir and out_dir identify different paths")
    value = artifact_dir if artifact_dir is not None else out_dir
    return (
        Path(value).expanduser().resolve()
        if value is not None
        else source.with_name(f"{source.stem}.native-rollback-artifacts")
    )


def _output_path(source: Path, value: str | Path | None) -> Path:
    return (
        Path(value).expanduser().resolve()
        if value is not None
        else source.with_name(f"{source.stem}.native-patched.apk")
    )


def _prepare_output_paths(source: Path, destination: Path, artifact_root: Path) -> None:
    paths = {
        "source APK": source,
        "output APK": destination,
        "artifact directory": artifact_root,
    }
    normalized = {name: os.path.normcase(str(path.resolve())) for name, path in paths.items()}
    if len(set(normalized.values())) != len(normalized):
        raise AndroidNativePatchError("source, output, and artifact paths must be distinct")
    if destination.exists():
        raise AndroidNativePatchError(f"output APK already exists: {destination}")
    if artifact_root.exists():
        raise AndroidNativePatchError(f"artifact directory already exists: {artifact_root}")
    try:
        destination.relative_to(artifact_root)
    except ValueError:
        pass
    else:
        raise AndroidNativePatchError("output APK cannot be placed inside the artifact directory")


def _require_apk(path: str | Path) -> Path:
    target = Path(path).expanduser().resolve()
    if not target.is_file():
        raise AndroidNativePatchError(f"APK does not exist or is not a file: {target}")
    if target.suffix.casefold() != ".apk":
        raise AndroidNativePatchError(f"APK input must use the .apk extension: {target}")
    if not zipfile.is_zipfile(target):
        raise AndroidNativePatchError(f"APK is not a readable ZIP archive: {target}")
    return target


def _load_json_mapping(
    value: Mapping[str, Any] | str | Path,
    *,
    label: str,
) -> tuple[dict[str, Any], Path | None]:
    if isinstance(value, Mapping):
        return dict(value), None
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise AndroidNativePatchError(f"{label} does not exist: {path}")
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise AndroidNativePatchError(f"{label} exceeds JSON size limit {_MAX_JSON_BYTES}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise AndroidNativePatchError(f"{label} must contain a JSON object")
    return dict(payload), path.parent


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AndroidNativePatchError(f"{label} must be an object")
    return dict(value)


def _sequence_of_mappings(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise AndroidNativePatchError(f"{label} must be an array")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        result.append(_mapping(item, f"{label}[{index}]"))
    return result


def _required_sha256(value: Any, label: str) -> str:
    text = str(value or "").casefold()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise AndroidNativePatchError(f"{label} must be a SHA-256 digest")
    return text


def _required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AndroidNativePatchError(f"{label} must be a non-empty string")
    return value.strip()


def _nonnegative_value(value: Any, *, field: str) -> int:
    if isinstance(value, bool):
        raise AndroidNativePatchError(f"{field} must be a non-negative integer")
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError as exc:
            raise AndroidNativePatchError(
                f"{field} must be a non-negative integer"
            ) from exc
    if not isinstance(value, int) or value < 0:
        raise AndroidNativePatchError(f"{field} must be a non-negative integer")
    return value


def _hex_byte_value(value: Any, *, field: str) -> bytes:
    if isinstance(value, bytes):
        result = value
    elif isinstance(value, str):
        compact = "".join(value.split())
        if compact.casefold().startswith("0x"):
            compact = compact[2:]
        if not compact or len(compact) % 2:
            raise AndroidNativePatchError(
                f"{field} must contain an even number of hexadecimal characters"
            )
        try:
            result = bytes.fromhex(compact)
        except ValueError as exc:
            raise AndroidNativePatchError(f"{field} must be hexadecimal bytes") from exc
    else:
        raise AndroidNativePatchError(f"{field} must be bytes or a hexadecimal string")
    if not result:
        raise AndroidNativePatchError(f"{field} must not be empty")
    return result


def _publish_copy_without_overwrite(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    if destination.exists() or temporary.exists():
        raise AndroidNativePatchError(f"output path already exists: {destination}")
    try:
        with source.open("rb") as input_handle, temporary.open("xb") as output_handle:
            shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        if destination.exists():
            raise AndroidNativePatchError(f"output path appeared during publication: {destination}")
        os.replace(temporary, destination)
    except Exception:
        _remove_file(temporary)
        raise


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    data = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    if len(data) > _MAX_JSON_BYTES:
        raise AndroidNativePatchError(f"JSON artifact exceeds size limit {_MAX_JSON_BYTES}: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _artifact(path: Path, kind: str) -> dict[str, Any]:
    return {
        "name": path.name,
        "path": str(path),
        "kind": kind,
        "size": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _check(
    name: str,
    passed: bool,
    details: Mapping[str, Any] | None = None,
    *,
    status: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "status": status or ("passed" if passed else "failed"),
        "details": dict(details or {}),
    }


def _first(mapping: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if mapping.get(name) not in (None, ""):
            return mapping[name]
    return None


def _password_argument(value: Any) -> str:
    text = str(value)
    return text if text.startswith(("pass:", "env:", "file:", "stdin")) else f"pass:{text}"


def _redact_command(command: Sequence[str]) -> list[str]:
    result = [str(item) for item in command]
    for index, item in enumerate(result):
        if item in {"--ks-pass", "--key-pass"}:
            if index + 1 < len(result):
                result[index + 1] = "<redacted>"
        elif item.startswith("--ks-pass="):
            result[index] = "--ks-pass=<redacted>"
        elif item.startswith("--key-pass="):
            result[index] = "--key-pass=<redacted>"
    return result


def _process_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    return text[-_MAX_PROCESS_OUTPUT:]


def _sha256_file(path: Path, *, max_bytes: int | None = None) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise AndroidNativePatchError(
                    f"file exceeds hashing limit {max_bytes}: {path}"
                )
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha256(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def _remove_file(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _failure(tool: str, exc: Exception, path: str | Path) -> ToolResult:
    return ToolResult(
        tool=tool,
        status="failed",
        error=f"{type(exc).__name__}: {exc}",
        data={
            "status": "failed",
            "valid": False,
            "source_apk_path": str(Path(path).expanduser()),
            "artifacts": [],
        },
    )


__all__ = [
    "AndroidNativePatchError",
    "ApkPatchLimits",
    "DEFAULT_APK_PATCH_LIMITS",
    "android_native_patch_apk",
    "patch_android_native_apk",
    "patch_apk_native_library",
    "verify_android_native_patch_apk",
    "verify_android_native_apk_patch",
    "rollback_android_native_patch_apk",
    "rollback_android_native_apk_patch",
]
