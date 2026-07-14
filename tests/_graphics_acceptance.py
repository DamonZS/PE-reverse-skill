from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


_SYNTHETIC_KEYS = {"synthetic", "mock", "simulated"}
_SYNTHETIC_TEXT_KEYS = {
    "provider",
    "provider_kind",
    "evidence_class",
    "provenance",
}


@dataclass(frozen=True)
class AcceptanceContext:
    fixture_id: str
    root: Path
    session_id: str


def acceptance_context(fixture_id: str) -> AcceptanceContext | None:
    configured = str(
        os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or ""
    ).strip()
    if not configured:
        return None
    root = Path(configured).expanduser().resolve()
    if root.parent.name != fixture_id:
        return None
    session_id = str(
        os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_SESSION_ID") or root.name
    ).strip()
    if not session_id or session_id != root.name:
        raise AssertionError("acceptance session id does not match its run directory")
    if not root.is_dir():
        raise AssertionError("acceptance run directory does not exist")
    return AcceptanceContext(fixture_id, root, session_id)


def required_pid(name: str = "REVERSE_ANALYZER_GRAPHICS_FIXTURE_PID") -> int:
    value = str(os.environ.get(name) or "").strip()
    try:
        pid = int(value, 10)
    except (TypeError, ValueError) as exc:
        raise AssertionError(f"{name} must contain a positive PID") from exc
    if pid <= 0 or pid > 0xFFFFFFFF:
        raise AssertionError(f"{name} must contain a positive PID")
    return pid


def target_identity(pid: int) -> dict[str, Any]:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise AssertionError("target PID must be a positive integer")
    return {
        "kind": "process",
        "pid": pid,
        "display_name": f"graphics-fixture-{pid}",
    }


def load_json(path: str | os.PathLike[str], *, maximum: int = 16 * 1024 * 1024) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise AssertionError(f"required JSON artifact does not exist: {source}")
    size = source.stat().st_size
    if size <= 0 or size > maximum:
        raise AssertionError(f"JSON artifact has an invalid size: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AssertionError(f"invalid JSON artifact {source}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise AssertionError(f"JSON artifact must contain an object: {source}")
    result = dict(payload)
    assert_non_synthetic(result)
    return result


def assert_non_synthetic(value: Any, *, location: str = "artifact") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key).casefold()
            child = f"{location}.{key}"
            if name in _SYNTHETIC_KEYS and item is True:
                raise AssertionError(f"{child} contains synthetic provenance")
            if name == "test_double" and item is True:
                raise AssertionError(f"{child} identifies a test double")
            if name in _SYNTHETIC_TEXT_KEYS and not isinstance(item, (Mapping, list)):
                text = str(item).casefold()
                if any(marker in text for marker in _SYNTHETIC_KEYS):
                    raise AssertionError(f"{child} contains synthetic provenance")
            assert_non_synthetic(item, location=child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_non_synthetic(item, location=f"{location}[{index}]")


def json_bytes(value: Mapping[str, Any]) -> bytes:
    assert_non_synthetic(value)
    return (
        json.dumps(
            dict(value),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def manifest_entry(path: str, payload: bytes, kind: str) -> dict[str, Any]:
    return {
        "path": _safe_relative(path).as_posix(),
        "kind": kind,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "materialized": True,
    }


def write_bundle(
    context: AcceptanceContext,
    artifacts: Mapping[str, Mapping[str, Any] | bytes | str],
) -> None:
    encoded: dict[Path, bytes] = {}
    for raw_path, value in artifacts.items():
        relative = _safe_relative(raw_path)
        destination = (context.root / Path(*relative.parts)).resolve()
        if not _inside(destination, context.root):
            raise AssertionError(f"acceptance artifact escapes run directory: {raw_path}")
        if destination.exists():
            raise AssertionError(f"acceptance artifact already exists: {destination}")
        if isinstance(value, Mapping):
            content = json_bytes(value)
        elif isinstance(value, str):
            content = value.encode("utf-8")
        elif isinstance(value, bytes):
            content = value
        else:
            raise AssertionError(f"unsupported acceptance artifact type: {raw_path}")
        if not content:
            raise AssertionError(f"acceptance artifact is empty: {raw_path}")
        encoded[destination] = content

    staged: list[tuple[Path, Path]] = []
    try:
        for destination, content in encoded.items():
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(
                f".{destination.name}.{os.getpid()}.acceptance.tmp"
            )
            if temporary.exists():
                raise AssertionError(f"staged acceptance artifact already exists: {temporary}")
            temporary.write_bytes(content)
            staged.append((temporary, destination))
        for temporary, destination in staged:
            temporary.replace(destination)
    finally:
        for temporary, _ in staged:
            if temporary.exists():
                temporary.unlink()


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise AssertionError("acceptance artifact path must be normalized POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AssertionError(f"unsafe acceptance artifact path: {value}")
    return path


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
