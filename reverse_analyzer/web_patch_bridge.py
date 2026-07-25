"""JSON bridge exposing the verified patch engine to the Go control plane."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from reverse_analyzer.tools.patch import binary_patch_apply_plan, binary_patch_rollback_plan


def _result(result: Any) -> dict[str, Any]:
    return {
        "status": result.status,
        "data": result.data or {},
        "error": result.error,
    }


def _read(payload: dict[str, Any], key: str) -> Path:
    path = Path(str(payload[key])).resolve()
    if not path.is_file():
        raise ValueError(f"{key} is not a file")
    return path


def inspect(payload: dict[str, Any]) -> dict[str, Any]:
    target = _read(payload, "target")
    data = target.read_bytes()
    offset = int(str(payload.get("offset", 0)), 0)
    length = int(payload.get("length", 16))
    if offset < 0 or length < 1 or length > 4096 or offset + length > len(data):
        raise ValueError("inspection range is outside the target")
    radius = min(64, max(16, int(payload.get("context", 32))))
    start, end = max(0, offset - radius), min(len(data), offset + length + radius)
    return {
        "status": "ok",
        "target": str(target),
        "target_sha256": hashlib.sha256(data).hexdigest(),
        "target_size": len(data),
        "offset": offset,
        "offset_hex": f"0x{offset:X}",
        "length": length,
        "expected_hex": data[offset : offset + length].hex(),
        "context_start": start,
        "context_hex": data[start:end].hex(),
    }


def apply(payload: dict[str, Any], *, write: bool) -> dict[str, Any]:
    result = binary_patch_apply_plan(
        _read(payload, "target"),
        plan=payload["plan"],
        out_path=Path(str(payload["output"])).resolve(),
        apply=write,
        artifact_dir=Path(str(payload["artifact_dir"])).resolve(),
    )
    return _result(result)


def rollback(payload: dict[str, Any], *, write: bool) -> dict[str, Any]:
    result = binary_patch_rollback_plan(
        _read(payload, "patched"),
        rollback=_read(payload, "rollback"),
        out_path=Path(str(payload["output"])).resolve(),
        apply=write,
        artifact_dir=Path(str(payload["artifact_dir"])).resolve(),
    )
    return _result(result)


def verify(payload: dict[str, Any]) -> dict[str, Any]:
    target = _read(payload, "target")
    expected = str(payload["sha256"]).lower()
    actual = hashlib.sha256(target.read_bytes()).hexdigest()
    return {"status": "ok" if actual == expected else "failed", "expected_sha256": expected, "actual_sha256": actual, "matches": actual == expected}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        action = str(payload.pop("action"))
        handlers = {
            "inspect": inspect,
            "plan": lambda value: apply(value, write=False),
            "apply": lambda value: apply(value, write=True),
            "verify": verify,
            "rollback-plan": lambda value: rollback(value, write=False),
            "rollback": lambda value: rollback(value, write=True),
        }
        if action not in handlers:
            raise ValueError("unsupported bridge action")
        output = handlers[action](payload)
        print(json.dumps(output, ensure_ascii=False))
        return 0 if output.get("status") in {"ok", "planned"} else 2
    except Exception as exc:  # bridge errors must remain structured for the API
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
