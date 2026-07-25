"""Token identities, workspace scoping, and role-based authorization."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Mapping

ROLES = {
    "viewer": {"workspace.read", "artifact.read"},
    "analyst": {"workspace.read", "artifact.read", "knowledge.write", "analysis.plan", "analysis.execute"},
    "admin": {"workspace.read", "artifact.read", "knowledge.write", "analysis.plan", "analysis.execute", "users.manage", "providers.manage"},
}


@dataclass(frozen=True)
class Identity:
    subject: str
    role: str
    workspace: str
    source: str

    def allows(self, permission: str, workspace: str) -> bool:
        return self.workspace in {"*", workspace} and permission in ROLES.get(self.role, set())


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLES.get(role, set())


def compare_token(token: str, expected_digest: str) -> bool:
    return hmac.compare_digest(token_digest(token), expected_digest)


class TokenRegistry:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def authenticate(self, token: str) -> Identity | None:
        if not token or not self.path.is_file():
            return None
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return None
        for record in payload.get("tokens", []) if isinstance(payload, Mapping) else []:
            if isinstance(record, Mapping) and not record.get("revoked") and compare_token(token, str(record.get("token_hash") or "")):
                role = str(record.get("role") or "viewer")
                if role not in ROLES:
                    return None
                return Identity(str(record.get("subject") or "api-token"), role, str(record.get("workspace") or "*"), "registry")
        return None


__all__ = ["ROLES", "Identity", "TokenRegistry", "token_digest", "has_permission", "compare_token"]
