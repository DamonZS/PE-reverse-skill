"""Local API tokens, RBAC, and workspace authorization for the Web platform."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile
from typing import Any, Iterable


ROLE_PERMISSIONS = {
    "viewer": frozenset({"workspace.read", "artifact.read", "knowledge.read"}),
    "analyst": frozenset({"workspace.read", "artifact.read", "knowledge.read", "knowledge.write", "experiment.plan", "experiment.execute", "experiment.cancel", "sample.upload"}),
    "admin": frozenset({"*"}),
}


@dataclass(frozen=True)
class Principal:
    user_id: str
    username: str
    role: str
    workspace_ids: frozenset[str]
    authentication: str = "api-token"

    def permits(self, permission: str, workspace_id: str) -> bool:
        allowed = ROLE_PERMISSIONS.get(self.role, frozenset())
        return ("*" in allowed or permission in allowed) and ("*" in self.workspace_ids or workspace_id in self.workspace_ids)


class LocalAuthStore:
    """Small local user/token store; tokens are only persisted as salted hashes."""

    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def create_user(self, user_id: str, username: str, role: str, workspace_ids: Iterable[str]) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValueError("invalid role")
        data = self._load()
        if any(item["id"] == user_id or item["username"] == username for item in data["users"]):
            raise ValueError("user id and username must be unique")
        record = {"id": user_id, "username": username, "role": role, "workspace_ids": sorted(set(workspace_ids)), "disabled": False}
        if not record["workspace_ids"]:
            raise ValueError("user requires at least one workspace")
        data["users"].append(record)
        self._save(data)
        return dict(record)

    def issue_token(self, user_id: str, *, label: str = "api") -> str:
        data = self._load()
        if not any(item["id"] == user_id and not item.get("disabled") for item in data["users"]):
            raise ValueError("active user not found")
        token = "ra_" + secrets.token_urlsafe(32)
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", token.encode(), salt, 200_000)
        data["tokens"].append({"id": secrets.token_hex(12), "user_id": user_id, "label": label, "salt": salt.hex(), "digest": digest.hex(), "disabled": False})
        self._save(data)
        return token

    def authenticate(self, token: str) -> Principal | None:
        if not token:
            return None
        data = self._load()
        matched_user_id = None
        for item in data["tokens"]:
            if item.get("disabled"):
                continue
            salt = bytes.fromhex(item["salt"])
            candidate = hashlib.pbkdf2_hmac("sha256", token.encode(), salt, 200_000).hex()
            if hmac.compare_digest(candidate, item["digest"]):
                matched_user_id = item["user_id"]
        if matched_user_id is None:
            return None
        user = next((item for item in data["users"] if item["id"] == matched_user_id and not item.get("disabled")), None)
        if user is None:
            return None
        return Principal(user["id"], user["username"], user["role"], frozenset(user["workspace_ids"]))

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"schema_version": 1, "users": [], "tokens": []}
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if value.get("schema_version") != 1:
            raise ValueError("unsupported local auth schema")
        return value

    def _save(self, value: dict[str, Any]) -> None:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.path.parent, delete=False) as handle:
            handle.write(payload)
            temporary = Path(handle.name)
        temporary.replace(self.path)


class AuthService:
    """Authenticate local tokens while preserving the legacy environment token."""

    def __init__(self, store: LocalAuthStore, *, legacy_token: str | None = None):
        self.store = store
        self.legacy_token = (legacy_token or "").strip() or None

    @classmethod
    def from_environment(cls, workspace: str | Path) -> "AuthService":
        auth_file = Path(os.environ.get("REVERSE_ANALYZER_AUTH_FILE", Path(workspace) / ".reverse_analyzer" / "web-auth.json"))
        return cls(LocalAuthStore(auth_file), legacy_token=os.environ.get("REVERSE_ANALYZER_WEB_TOKEN"))

    def authenticate(self, token: str) -> Principal | None:
        if self.legacy_token is not None and hmac.compare_digest(token, self.legacy_token):
            return Principal("legacy-env", "legacy-env-token", "admin", frozenset({"*"}), "legacy-env-token")
        return self.store.authenticate(token)

    def authorize(self, token: str, permission: str, workspace_id: str) -> Principal:
        principal = self.authenticate(token)
        if principal is None:
            raise PermissionError("authentication required")
        if not principal.permits(permission, workspace_id):
            raise PermissionError("workspace or role does not permit this operation")
        return principal


def bearer_or_api_key(authorization: str | None, api_key: str | None) -> str:
    header = (authorization or "").strip()
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return (api_key or "").strip()
