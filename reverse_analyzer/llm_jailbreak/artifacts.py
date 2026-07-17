from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from .instruction_assets import InstructionBundle
from .models import Attempt, Campaign, CampaignResult, utc_now


SCHEMA_VERSION = 1

_WINDOWS_RESERVED_NAMES = {
    "aux",
    "clock$",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "con",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
    "nul",
    "prn",
}


def _safe_instruction_filename(
    name: str,
    index: int,
    used_names: set[str],
) -> str:
    leaf_name = name.replace("\\", "/").rsplit("/", 1)[-1]
    lowered = leaf_name.casefold()
    for suffix in (".markdown", ".md"):
        if lowered.endswith(suffix):
            leaf_name = leaf_name[: -len(suffix)]
            break

    safe_name = "".join(
        character
        if character.isascii() and (character.isalnum() or character in "._-")
        else "-"
        for character in leaf_name
    ).strip("._-")
    safe_name = safe_name[:96].rstrip("._-")
    if not safe_name:
        safe_name = f"instruction-{index + 1}"
    if safe_name.casefold() in _WINDOWS_RESERVED_NAMES:
        safe_name = f"instruction-{safe_name}"

    candidate = f"{safe_name}.md"
    suffix_index = 2
    while candidate.casefold() in used_names:
        candidate = f"{safe_name}-{suffix_index}.md"
        suffix_index += 1
    used_names.add(candidate.casefold())
    return candidate


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    atomic_write_bytes(path, encoded)


def load_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {path}")
    return value


def write_checkpoint(path: Path, payload: Mapping[str, Any]) -> None:
    data = dict(payload)
    data["schema_version"] = SCHEMA_VERSION
    data["updated_at"] = utc_now()
    atomic_write_json(path, data)


class ArtifactWriter:
    def __init__(self, out_dir: Path) -> None:
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.prompts_dir = self.out_dir / "prompts"
        self.responses_dir = self.out_dir / "responses"

    def artifact_paths(
        self,
        checkpoint_path: Optional[Path] = None,
        *,
        instruction_bundle: InstructionBundle | None = None,
    ) -> Dict[str, str]:
        paths = {
            "campaign": "campaign.json",
            "attempts": "attempts.json",
            "attempt_log": "attempts.jsonl",
            "transcript": "transcript.json",
            "result": "result.json",
            "manifest": "manifest.json",
            "prompts": "prompts/",
            "responses": "responses/",
        }
        if instruction_bundle is not None and not isinstance(
            instruction_bundle, InstructionBundle
        ):
            raise TypeError("instruction_bundle must be an InstructionBundle")
        if instruction_bundle is not None and instruction_bundle.assets:
            paths["instruction_assets"] = "instruction-assets.json"
            paths["instructions"] = "instructions/"
        if checkpoint_path is not None:
            try:
                paths["checkpoint"] = checkpoint_path.relative_to(self.out_dir).as_posix()
            except ValueError:
                paths["checkpoint"] = str(checkpoint_path.resolve())
        return paths

    def write_attempt(self, attempt: Attempt) -> None:
        safe_name = "".join(
            character if character.isalnum() or character in "._-" else "-"
            for character in attempt.attempt_id
        )
        atomic_write_bytes(
            self.prompts_dir / f"{safe_name}.txt",
            (attempt.prompt + "\n").encode("utf-8"),
        )
        response_text = attempt.response.content if attempt.response else ""
        if attempt.error:
            response_text = f"ERROR: {attempt.error}\n{response_text}"
        atomic_write_bytes(
            self.responses_dir / f"{safe_name}.txt",
            (response_text + ("" if response_text.endswith("\n") else "\n")).encode("utf-8"),
        )

    def write_instruction_bundle(self, bundle: InstructionBundle) -> Sequence[Path]:
        if not isinstance(bundle, InstructionBundle):
            raise TypeError("instruction_bundle must be an InstructionBundle")

        instructions_dir = self.out_dir / "instructions"
        used_names: set[str] = set()
        asset_paths = []
        serialized_assets = []
        for index, asset in enumerate(bundle.assets):
            filename = _safe_instruction_filename(asset.name, index, used_names)
            artifact_path = instructions_dir / filename
            atomic_write_bytes(artifact_path, asset.content.encode("utf-8"))
            asset_paths.append(artifact_path)

            serialized_asset = asset.to_dict()
            serialized_asset["artifact_path"] = artifact_path.relative_to(
                self.out_dir
            ).as_posix()
            serialized_assets.append(serialized_asset)

        bundle_payload = bundle.to_dict()
        bundle_payload["schema_version"] = SCHEMA_VERSION
        bundle_payload["assets"] = serialized_assets
        bundle_path = self.out_dir / "instruction-assets.json"
        atomic_write_json(bundle_path, bundle_payload)
        return (bundle_path, *asset_paths)

    def finalize(
        self,
        campaign: Campaign,
        result: CampaignResult,
        *,
        checkpoint_path: Optional[Path] = None,
        instruction_bundle: InstructionBundle | None = None,
    ) -> Dict[str, str]:
        campaign_payload = campaign.to_dict()
        if instruction_bundle is not None:
            source_refs = [
                asset.source
                for asset in instruction_bundle.assets
                if asset.provenance.get("kind") == "custom-markdown"
            ]
            if source_refs:
                campaign_payload["instruction_files"] = source_refs
            else:
                campaign_payload.pop("instruction_files", None)
        atomic_write_json(self.out_dir / "campaign.json", campaign_payload)
        attempts_payload = {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": campaign.id,
            "attempts": [item.to_dict() for item in result.attempts],
        }
        atomic_write_json(self.out_dir / "attempts.json", attempts_payload)
        json_lines = "".join(
            json.dumps(item.to_dict(), sort_keys=True, ensure_ascii=False) + "\n"
            for item in result.attempts
        )
        atomic_write_bytes(self.out_dir / "attempts.jsonl", json_lines.encode("utf-8"))
        transcript = {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": campaign.id,
            "turns": [
                {
                    "attempt_id": item.attempt_id,
                    "strategy": item.strategy,
                    "attack_mode": item.metadata.get("attack_mode", "builtin"),
                    "round_index": item.round_index,
                    "prompt": item.prompt,
                    "response": item.response.content if item.response else "",
                    "score": item.score.to_dict() if item.score else None,
                    "error": item.error,
                    "metadata": dict(item.metadata),
                }
                for item in result.attempts
            ],
        }
        atomic_write_json(self.out_dir / "transcript.json", transcript)
        for attempt in result.attempts:
            self.write_attempt(attempt)
        atomic_write_json(self.out_dir / "result.json", result.to_dict())
        instruction_paths: Sequence[Path] = ()
        if instruction_bundle is not None and not isinstance(
            instruction_bundle, InstructionBundle
        ):
            raise TypeError("instruction_bundle must be an InstructionBundle")
        if instruction_bundle is not None and instruction_bundle.assets:
            instruction_paths = self.write_instruction_bundle(instruction_bundle)
        self._write_manifest(
            campaign.id,
            result.attempts,
            checkpoint_path,
            instruction_paths=instruction_paths,
        )
        return self.artifact_paths(
            checkpoint_path,
            instruction_bundle=instruction_bundle,
        )

    def _write_manifest(
        self,
        campaign_id: str,
        attempts: Sequence[Attempt],
        checkpoint_path: Optional[Path],
        *,
        instruction_paths: Sequence[Path] = (),
    ) -> None:
        manifest_path = self.out_dir / "manifest.json"
        entries = []
        expected_paths = [
            self.out_dir / "campaign.json",
            self.out_dir / "attempts.json",
            self.out_dir / "attempts.jsonl",
            self.out_dir / "transcript.json",
            self.out_dir / "result.json",
        ]
        expected_paths.extend(instruction_paths)
        for attempt in attempts:
            safe_name = "".join(
                character if character.isalnum() or character in "._-" else "-"
                for character in attempt.attempt_id
            )
            expected_paths.extend(
                [
                    self.prompts_dir / f"{safe_name}.txt",
                    self.responses_dir / f"{safe_name}.txt",
                ]
            )
        if checkpoint_path is not None:
            try:
                checkpoint_path.relative_to(self.out_dir)
            except ValueError:
                pass
            else:
                expected_paths.append(checkpoint_path)

        for path in sorted(set(expected_paths)):
            if not path.is_file():
                continue
            content = path.read_bytes()
            entries.append(
                {
                    "path": path.relative_to(self.out_dir).as_posix(),
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
        atomic_write_json(
            manifest_path,
            {
                "schema_version": SCHEMA_VERSION,
                "campaign_id": campaign_id,
                "generated_at": utc_now(),
                "artifact_count": len(entries),
                "artifacts": entries,
            },
        )
