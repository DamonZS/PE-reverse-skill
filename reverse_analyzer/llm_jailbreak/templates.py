from __future__ import annotations

import hashlib
import os
import tempfile
from importlib import resources
from pathlib import Path
from typing import Any, Mapping


TEMPLATE_FILES = (
    "jailbreak-campaign.example.json",
    "jailbreak-campaign.schema.json",
)


def _template_bytes(name: str) -> bytes:
    if name not in TEMPLATE_FILES:
        raise ValueError(f"unknown release template: {name}")
    return resources.files(__package__).joinpath("templates", name).read_bytes()


def initialize_workspace(
    directory: str | Path, *, force: bool = False
) -> Mapping[str, Any]:
    """Materialize packaged campaign assets without depending on a source checkout."""

    root = Path(directory).expanduser().resolve()
    if root.exists() and not root.is_dir():
        raise OSError(f"initialization path is not a directory: {root}")

    targets = tuple((name, root / name) for name in TEMPLATE_FILES)
    existing = [path.name for _, path in targets if path.exists()]
    if existing and not force:
        raise FileExistsError(
            "refusing to overwrite existing initialization files: "
            + ", ".join(sorted(existing))
        )
    invalid = [path.name for _, path in targets if path.exists() and not path.is_file()]
    if invalid:
        raise OSError(
            "initialization target is not a regular file: "
            + ", ".join(sorted(invalid))
        )

    contents = tuple((name, target, _template_bytes(name)) for name, target in targets)
    root.mkdir(parents=True, exist_ok=True)
    written: list[Mapping[str, Any]] = []
    for name, target, content in contents:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=root, prefix=f".{name}.", suffix=".tmp"
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        written.append(
            {
                "path": target.name,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return {"directory": str(root), "files": written}
