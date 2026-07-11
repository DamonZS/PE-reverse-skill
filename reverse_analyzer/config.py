"""Configuration helpers for the reverse-analyzer CLI scaffold."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict


DEFAULT_KNOWLEDGE_DIR = ".reverse_analyzer/knowledge"
DEFAULT_SESSIONS_DIR = ".reverse_analyzer/sessions"
DEFAULT_REPORTS_DIR = "reports"
DEFAULT_DASHBOARD_PORT = 8088


@dataclass(frozen=True)
class AnalyzerConfig:
    """Runtime locations used by the PE migration scaffold."""

    workspace: Path
    knowledge_dir: Path
    sessions_dir: Path
    reports_dir: Path
    dashboard_port: int = DEFAULT_DASHBOARD_PORT

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for key in ("workspace", "knowledge_dir", "sessions_dir", "reports_dir"):
            data[key] = str(data[key])
        return data


def load_config(workspace: str | Path | None = None) -> AnalyzerConfig:
    """Build config from environment variables and an optional workspace."""

    root = Path(workspace or os.environ.get("REVERSE_ANALYZER_WORKSPACE", ".")).resolve()
    knowledge_dir = Path(os.environ.get("REVERSE_ANALYZER_KNOWLEDGE_DIR", root / DEFAULT_KNOWLEDGE_DIR))
    sessions_dir = Path(os.environ.get("REVERSE_ANALYZER_SESSIONS_DIR", root / DEFAULT_SESSIONS_DIR))
    reports_dir = Path(os.environ.get("REVERSE_ANALYZER_REPORTS_DIR", root / DEFAULT_REPORTS_DIR))
    dashboard_port = int(os.environ.get("REVERSE_ANALYZER_DASHBOARD_PORT", DEFAULT_DASHBOARD_PORT))
    return AnalyzerConfig(
        workspace=root,
        knowledge_dir=knowledge_dir.resolve(),
        sessions_dir=sessions_dir.resolve(),
        reports_dir=reports_dir.resolve(),
        dashboard_port=dashboard_port,
    )


def ensure_runtime_dirs(config: AnalyzerConfig) -> None:
    """Create directories used by sessions, reports, and persistent knowledge."""

    config.knowledge_dir.mkdir(parents=True, exist_ok=True)
    config.sessions_dir.mkdir(parents=True, exist_ok=True)
    config.reports_dir.mkdir(parents=True, exist_ok=True)


def write_default_knowledge(config: AnalyzerConfig) -> Path:
    """Initialize a small JSON knowledge manifest if one does not exist."""

    ensure_runtime_dirs(config)
    manifest = config.knowledge_dir / "knowledge.json"
    if not manifest.exists():
        manifest.write_text(
            json.dumps(
                {
                    "version": 1,
                    "providers": [],
                    "tool_notes": {},
                    "reports": [],
                    "description": "PE migration knowledge scaffold for reverse-analyzer.",
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
    return manifest
