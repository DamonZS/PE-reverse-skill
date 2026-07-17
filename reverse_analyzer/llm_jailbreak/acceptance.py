from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from reverse_analyzer.evidence.manifest import verify_manifest

from .artifacts import atomic_write_json
from .instruction_assets import InstructionBundle
from .models import Campaign


_SECRET_PATTERN = re.compile(
    rb"(?i)(authorization['\"]?\s*[:=]|bearer\s+[a-z0-9._~+/-]{8,}|"
    rb"(?:api[_-]?key|token|secret)['\"]?\s*[:=]\s*['\"]?"
    rb"(?!\*{3}|<redacted>)[^\s,'\"}]{8,})"
)
_WINDOWS_ABSOLUTE = re.compile(
    rb"(?i)(?:(?<![a-z])[a-z]:[\\/]|\\\\[^\\\s]+[\\/][^\\\s]+)"
)
_POSIX_HOST_ABSOLUTE = re.compile(rb"/(?:home|users|root|tmp|var/tmp)/[^\s\"']+")


@dataclass(frozen=True)
class PromotionResult:
    status: str
    root: Path
    engine_dir: Path
    checks: tuple[Mapping[str, Any], ...]
    acceptance_digest: str
    promotion_path: Path

    @property
    def ok(self) -> bool:
        return self.status == "passed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "reverse_analyzer.llm_jailbreak.promotion/v1",
            "status": self.status,
            "engine_path": self.engine_dir.relative_to(self.root).as_posix()
            if self.engine_dir != self.root
            else ".",
            "acceptance_digest": self.acceptance_digest,
            "checks": [dict(item) for item in self.checks],
        }


def _load(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, Mapping):
        raise ValueError(f"JSON root must be an object: {path.name}")
    return value


def _discover(root: Path) -> Path:
    candidates = []
    for candidate in (root, root / "engine"):
        if (candidate / "result.json").is_file():
            candidates.append(candidate)
    candidates.extend(
        path.parent for path in root.glob("llm_jailbreak/*/engine/result.json")
    )
    unique = {item.resolve() for item in candidates}
    if not unique:
        raise ValueError("no standalone or platform jailbreak engine output was found")
    return max(unique, key=lambda item: (item / "result.json").stat().st_mtime_ns)


def _check(name: str, failures: Sequence[str], **details: Any) -> dict[str, Any]:
    return {
        "name": name,
        "status": "failed" if failures else "passed",
        "failures": list(failures),
        **details,
    }


def _scan_json_value(
    value: Any,
    *,
    location: str,
    secret_values: Sequence[bytes],
) -> list[str]:
    failures: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{location}.{key}"
            if str(key).strip().casefold() == "authorization":
                failures.append(f"authorization header: {child}")
            failures.extend(
                _scan_json_value(item, location=child, secret_values=secret_values)
            )
    elif isinstance(value, list):
        for index, item in enumerate(value):
            failures.extend(
                _scan_json_value(
                    item,
                    location=f"{location}[{index}]",
                    secret_values=secret_values,
                )
            )
    elif isinstance(value, str):
        data = value.encode("utf-8")
        if _SECRET_PATTERN.search(data) or any(secret in data for secret in secret_values):
            failures.append(f"secret-like value: {location}")
        leaf = location.rsplit(".", 1)[-1]
        operational_path = (
            leaf
            in {
                "path",
                "campaign_path",
                "checkpoint_path",
                "out_dir",
                "collection_root",
                "report_json",
                "report_md",
            }
            or location.endswith(".artifacts.checkpoint")
            or re.search(r"\.(?:artifacts|artifact_paths)\[\d+\]$", location) is not None
        )
        if (
            not operational_path
            and (_WINDOWS_ABSOLUTE.search(data) or _POSIX_HOST_ABSOLUTE.search(data))
        ):
            failures.append(f"host absolute path: {location}")
    return failures


def _verify_engine_manifest(engine: Path) -> tuple[list[str], int]:
    manifest = _load(engine / "manifest.json")
    records = manifest.get("artifacts")
    if not isinstance(records, list):
        return ["manifest artifacts must be an array"], 0
    failures: list[str] = []
    verified = 0
    for record in records:
        if not isinstance(record, Mapping) or not isinstance(record.get("path"), str):
            failures.append("manifest contains an invalid artifact record")
            continue
        relative = Path(str(record["path"]))
        target = (engine / relative).resolve()
        try:
            target.relative_to(engine)
        except ValueError:
            failures.append(f"artifact escapes engine directory: {relative.as_posix()}")
            continue
        if not target.is_file():
            failures.append(f"missing artifact: {relative.as_posix()}")
            continue
        content = target.read_bytes()
        if len(content) != record.get("size"):
            failures.append(f"size mismatch: {relative.as_posix()}")
            continue
        if hashlib.sha256(content).hexdigest() != record.get("sha256"):
            failures.append(f"hash mismatch: {relative.as_posix()}")
            continue
        verified += 1
    return failures, verified


def _find_checkpoint(
    root: Path,
    engine: Path,
    result: Mapping[str, Any],
    campaign: Campaign,
) -> Path | None:
    direct = engine / "checkpoint.json"
    if direct.is_file():
        return direct
    artifacts = result.get("artifacts")
    raw = artifacts.get("checkpoint") if isinstance(artifacts, Mapping) else None
    if isinstance(raw, str) and raw and "<redacted>" not in raw:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = engine / candidate
        if candidate.is_file():
            return candidate.resolve()
    checkpoint_root = root / "llm_jailbreak" / "checkpoints"
    exact = checkpoint_root / f"{campaign.fingerprint()}.json"
    if exact.is_file():
        return exact
    for candidate in checkpoint_root.glob("*.json"):
        try:
            payload = _load(candidate)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if (
            payload.get("campaign_id") == campaign.id
            and payload.get("campaign_fingerprint") == campaign.fingerprint()
        ):
            return candidate
    return None


def promote_output(path: str | Path, *, secret_env_names: Sequence[str] = ()) -> PromotionResult:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"promotion root is not a directory: {root}")
    engine = _discover(root)
    checks: list[Mapping[str, Any]] = []
    required = ("campaign.json", "attempts.json", "transcript.json", "result.json", "manifest.json")
    missing = [name for name in required if not (engine / name).is_file()]
    checks.append(_check("required_artifacts", missing, required=list(required)))
    if missing:
        return _finish(root, engine, checks)

    campaign_payload = _load(engine / "campaign.json")
    attempts_payload = _load(engine / "attempts.json")
    transcript = _load(engine / "transcript.json")
    result = _load(engine / "result.json")
    campaign = Campaign.from_dict(campaign_payload)
    attempts = attempts_payload.get("attempts")
    turns = transcript.get("turns")
    result_attempts = result.get("attempts")
    sequence_failures: list[str] = []
    if not isinstance(attempts, list) or not isinstance(turns, list) or not isinstance(result_attempts, list):
        sequence_failures.append("attempts, transcript turns, and result attempts must be arrays")
        attempts, turns, result_attempts = [], [], []
    ids = [str(item.get("attempt_id", "")) for item in attempts if isinstance(item, Mapping)]
    turn_ids = [str(item.get("attempt_id", "")) for item in turns if isinstance(item, Mapping)]
    result_ids = [str(item.get("attempt_id", "")) for item in result_attempts if isinstance(item, Mapping)]
    if not ids or ids != turn_ids or ids != result_ids:
        sequence_failures.append("attempt IDs are empty or inconsistent across artifacts")
    if result.get("attempt_count") != len(ids):
        sequence_failures.append("result attempt_count is inconsistent")
    if any(item.get("campaign_id") != campaign.id for item in attempts if isinstance(item, Mapping)):
        sequence_failures.append("attempt campaign identity is inconsistent")
    checks.append(_check("attempts_transcript", sequence_failures, attempt_count=len(ids)))

    transport_failures = []
    endpoints = set()
    for item in attempts:
        response = item.get("response") if isinstance(item, Mapping) else None
        metadata = response.get("metadata") if isinstance(response, Mapping) else None
        if not isinstance(metadata, Mapping):
            transport_failures.append(f"attempt {item.get('attempt_id', '')} lacks response metadata")
            continue
        endpoint = metadata.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint.startswith(("http://", "https://")):
            transport_failures.append(f"attempt {item.get('attempt_id', '')} lacks HTTP endpoint evidence")
        else:
            endpoints.add(endpoint)
        if metadata.get("provider_response_type") != "chat.completion":
            transport_failures.append(f"attempt {item.get('attempt_id', '')} lacks chat completion evidence")
    checks.append(_check("http_transport", transport_failures, endpoints=sorted(endpoints)))

    checkpoint_path = _find_checkpoint(root, engine, result, campaign)
    checkpoint_failures: list[str] = []
    checkpoint: Mapping[str, Any] = {}
    if checkpoint_path is None:
        checkpoint_failures.append("checkpoint was not found")
    else:
        checkpoint = _load(checkpoint_path)
        if checkpoint.get("campaign_id") != campaign.id:
            checkpoint_failures.append("checkpoint campaign ID mismatch")
        if checkpoint.get("campaign_fingerprint") != campaign.fingerprint():
            checkpoint_failures.append("checkpoint campaign fingerprint mismatch")
        checkpoint_attempts = checkpoint.get("attempts")
        checkpoint_ids = [
            str(item.get("attempt_id", ""))
            for item in checkpoint_attempts or []
            if isinstance(item, Mapping)
        ]
        if checkpoint_ids != ids:
            checkpoint_failures.append("checkpoint attempts do not match final attempts")
        if not checkpoint.get("completed"):
            checkpoint_failures.append("checkpoint is not complete")
    checks.append(_check("checkpoint", checkpoint_failures))

    instruction_failures: list[str] = []
    instruction_path = engine / "instruction-assets.json"
    if instruction_path.is_file():
        try:
            bundle = InstructionBundle.from_dict(_load(instruction_path))
            if checkpoint.get("instruction_bundle_digest") != bundle.digest:
                instruction_failures.append("instruction bundle digest mismatch")
        except (TypeError, ValueError) as exc:
            instruction_failures.append(str(exc))
    else:
        empty_digest = InstructionBundle().digest
        if checkpoint and checkpoint.get("instruction_bundle_digest") != empty_digest:
            instruction_failures.append("missing instruction snapshot for non-empty bundle")
    checks.append(_check("instruction_bundle", instruction_failures))

    judge_failures: list[str] = []
    for item in attempts:
        if not isinstance(item, Mapping) or not isinstance(item.get("score"), Mapping):
            judge_failures.append("attempt lacks traceable score")
            continue
        metadata = item.get("metadata")
        if not isinstance(metadata, Mapping) or not isinstance(metadata.get("final_success"), bool):
            judge_failures.append(f"attempt {item.get('attempt_id', '')} lacks final_success")
        if campaign.semantic_judge != "disabled":
            verdict = metadata.get("semantic_judge_verdict") if isinstance(metadata, Mapping) else None
            if not isinstance(verdict, Mapping) or not isinstance(verdict.get("success"), bool):
                judge_failures.append(f"attempt {item.get('attempt_id', '')} lacks semantic verdict")
    checks.append(_check("semantic_judge", judge_failures, mode=campaign.semantic_judge))

    manifest_failures, verified = _verify_engine_manifest(engine)
    checks.append(_check("engine_manifest", manifest_failures, verified_file_count=verified))
    evidence_path = root / "evidence-manifest.json"
    evidence_failures: list[str] = []
    evidence_verified = 0
    if evidence_path.is_file():
        verification = verify_manifest(evidence_path)
        evidence_verified = int(verification.get("verified_file_count", 0))
        if not verification.get("valid"):
            evidence_failures.extend(
                str(item.get("kind", "verification failure"))
                for item in verification.get("issues", [])
                if isinstance(item, Mapping)
            )
    checks.append(_check("evidence_manifest", evidence_failures, applicable=evidence_path.is_file(), verified_file_count=evidence_verified))

    secret_values = [
        os.getenv(name, "").encode("utf-8")
        for name in secret_env_names
        if name and os.getenv(name)
    ]
    scan_failures: list[str] = []
    scan_root = root if engine != root else engine
    for file_path in scan_root.rglob("*"):
        if not file_path.is_file() or file_path.name == "promotion.json":
            continue
        data = file_path.read_bytes()
        relative = file_path.relative_to(scan_root).as_posix()
        if file_path.suffix.casefold() in {".json", ".jsonl"}:
            try:
                if file_path.suffix.casefold() == ".jsonl":
                    values = [json.loads(line) for line in data.decode("utf-8-sig").splitlines() if line.strip()]
                else:
                    values = [json.loads(data.decode("utf-8-sig"))]
            except (UnicodeDecodeError, json.JSONDecodeError):
                values = []
            if values:
                for index, value in enumerate(values):
                    location = relative if len(values) == 1 else f"{relative}[{index}]"
                    scan_failures.extend(
                        _scan_json_value(
                            value,
                            location=location,
                            secret_values=secret_values,
                        )
                    )
                continue
        if _SECRET_PATTERN.search(data) or any(secret in data for secret in secret_values):
            scan_failures.append(f"secret-like value: {relative}")
        if _WINDOWS_ABSOLUTE.search(data) or _POSIX_HOST_ABSOLUTE.search(data):
            scan_failures.append(f"host absolute path: {relative}")
    checks.append(_check("redaction_scan", scan_failures, scanned_root="."))
    return _finish(root, engine, checks)


def _finish(root: Path, engine: Path, checks: Sequence[Mapping[str, Any]]) -> PromotionResult:
    status = "passed" if all(item.get("status") == "passed" for item in checks) else "failed"
    digest_input = json.dumps(list(checks), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(digest_input).hexdigest()
    target = root / "promotion.json"
    result = PromotionResult(status, root, engine, tuple(checks), digest, target)
    atomic_write_json(target, result.to_dict())
    return result
