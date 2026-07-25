"""Read the executable capability parity contract into a machine-readable audit."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any


PARITY_STATUSES = {"done", "dependency-gated", "partial", "missing"}


def audit_capability_coverage(matrix_path: str | Path) -> dict[str, Any]:
    path = Path(matrix_path)
    rows = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.startswith("|"):
            continue
        columns = [column.strip() for column in line.strip("|").split("|")]
        if len(columns) < 9 or columns[1] not in PARITY_STATUSES:
            continue
        rows.append(
            {
                "capability": columns[0],
                "status": columns[1],
                "modules": columns[2],
                "gap": columns[3],
                "phase": columns[7],
                "acceptance_command": columns[8],
            }
        )
    counts = Counter(row["status"] for row in rows)
    unresolved = [row for row in rows if row["status"] != "done"]
    return {
        "status": "complete" if rows and not unresolved else "incomplete",
        "capability_count": len(rows),
        "counts": {status: counts.get(status, 0) for status in sorted(PARITY_STATUSES)},
        "done_ratio": round(counts.get("done", 0) / len(rows), 4) if rows else 0.0,
        "unresolved_count": len(unresolved),
        "unresolved": unresolved,
        "policy": "Only production code, non-mock tests, and required retained live evidence may promote a capability to done.",
    }
