"""Cursor platform adapter.

Cursor loads rules from ``.cursor/rules/*.mdc``.  A rule whose frontmatter
declares ``alwaysApply: true`` is included at the start of the model context
for *every* chat session in that project --- the closest analogue to Codex's
``model_instructions_file``.  Because Cursor scopes project rules to a repo
(``.cursor/rules``), this adapter targets an explicit project directory (or the
default ``~/.cursor`` root) and writes a branded ``alwaysApply`` rule.  An
``AGENTS.md`` is dropped as a plain-markdown fallback.

Safety mirrors the shared model: ``allowed=True`` (or ``force``) gates any
write; each edit is atomic and reversible; a restore undoes the change.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..adapter import (
    DeployPlan,
    EvidenceEntry,
    InstructionDeployError,
    Operation,
    PLATFORM_CURSOR,
    PlatformAdapter,
    atomic_write,
    backup_existing,
    confine,
    read_text_optional,
    sha256_str,
)

RULES_DIRNAME = ".cursor/rules"
RULE_FILENAME = "topo.ac.mdc"
AGENTS_MD_FILENAME = "AGENTS.md"


def cursor_default_target() -> Path:
    """Return the recommended project-level root for a Cursor rule set.

    We default to ``~/.cursor`` (the user config root) so the adapter operates
    on the user's global Cursor directory.  A caller may pass an explicit
    project directory (which contains a ``.cursor`` subdir) instead.
    """
    return Path("~/.cursor").expanduser()


def _rule_frontmatter() -> str:
    return "---\nalwaysApply: true\n---\n"


class CursorAdapter(PlatformAdapter):
    platform = PLATFORM_CURSOR

    def default_target(self) -> Path:
        return cursor_default_target()

    def _rules_dir(self, root: Path) -> Path:
        # If the caller passes a *project* directory, Cursor expects
        # ``<project>/.cursor/rules``.  If they pass the ``~/.cursor`` config
        # dir itself, Cursor's project rules live at ``<dir>/rules``.
        if root.name == ".cursor":
            return root / "rules"
        return root / ".cursor" / "rules"

    def _rule_path(self, root: Path) -> Path:
        return self._rules_dir(root) / RULE_FILENAME

    def _rule_rel(self, root: Path) -> str:
        """Relative path from the target root to the rule file.

        Computed from the actual rules dir so that backup and write always
        agree with the path ``_rule_path`` returns, regardless of whether the
        target is a project root or the ``~/.cursor`` config dir.
        """
        try:
            return self._rule_path(root).relative_to(root.resolve()).as_posix()
        except ValueError:
            # Fallback for display only.
            return f"{RULES_DIRNAME}/{RULE_FILENAME}"

    def _load_content(self, instruction_profile: str) -> str:
        # Always load the branded topology bundle for Cursor rules.  Cursor
        # wraps it in its .mdc frontmatter; the body is the topo identity.
        from reverse_analyzer.llm_jailbreak.instruction_assets import (
            load_instruction_bundle,
        )

        canonical = instruction_profile or "topo-ac-unrestricted"
        bundle = load_instruction_bundle(canonical)
        return bundle.content

    def describe(self, target: Path | None = None) -> DeployPlan:
        root = (target or self.default_target()).expanduser().resolve()
        rule_path = self._rule_path(root)
        rule_rel = self._rule_rel(root)
        notes = []
        if not rule_path.parent.is_dir():
            notes.append(f"will create {rule_path.parent.as_posix()}")
        if rule_path.is_file():
            notes.append("will overwrite existing topo.ac.mdc (backed up)")
        operations = [
            Operation(
                rel_path=rule_rel,
                kind="create",
                description="alwaysApply Cursor rule carrying the topo identity",
            ),
        ]
        # AGENTS.md fallback is written only for a project root, matching deploy.
        if root.name != ".cursor":
            operations.append(
                Operation(
                    rel_path=AGENTS_MD_FILENAME,
                    kind="create",
                    description="plain-markdown AGENTS.md fallback",
                )
            )
        return DeployPlan(
            platform=self.platform,
            target=str(root),
            operations=tuple(operations),
            notes=tuple(notes),
        )

    def inspect(self, target: Path | None = None) -> Mapping[str, Any]:
        root = (target or self.default_target()).expanduser().resolve()
        rule_path = self._rule_path(root)
        rule_exists = rule_path.is_file()
        content = read_text_optional(rule_path)
        findings = []
        if rule_exists:
            findings.append(
                {
                    "severity": "notice",
                    "code": "cursor-rule-present",
                    "message": "topo alwaysApply rule present under .cursor/rules",
                    "path": rule_path.as_posix(),
                }
            )
            if "拓扑" in content or "alwaysApply" in content:
                findings.append(
                    {
                        "severity": "warning",
                        "code": "cursor-instruction-injected",
                        "message": "branded instruction rule present in Cursor rules",
                        "path": rule_path.as_posix(),
                    }
                )
        else:
            findings.append(
                {
                    "severity": "info",
                    "code": "cursor-no-rule",
                    "message": "no topo rule present in .cursor/rules",
                    "path": rule_path.as_posix(),
                }
            )
        return {
            "platform": self.platform,
            "root": str(root),
            "exists": root.is_dir(),
            "rule_path": str(rule_path),
            "rule_present": rule_exists,
            "always_apply": "alwaysApply" in content,
            "findings": findings,
        }

    def deploy(
        self,
        target: Path | None = None,
        *,
        allowed: bool = False,
        force: bool = False,
        dry_run: bool = False,
        instruction_profile: str = "",
    ) -> Mapping[str, Any]:
        root = (target or self.default_target()).expanduser().resolve()

        # dry-run is a zero-side-effect preview: it must not require --allowed.
        if dry_run:
            return {
                "platform": self.platform,
                "status": "dry-run",
                "plan": self.describe(root).to_dict(),
            }

        if not allowed and not force:
            raise InstructionDeployError(
                "deployment not permitted: pass allowed=True (or --allowed) to confirm "
                f"you own/are authorized to instrument {root}, or use --force for a "
                "target you fully control"
            )

        rule_rel = self._rule_rel(root)
        body = self._load_content(instruction_profile or "topo-ac-unrestricted")
        rule_content = _rule_frontmatter() + body
        rule_path = self._rule_path(root)
        rule_backup = backup_existing(root, rule_rel)
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(rule_path, rule_content.encode("utf-8"))

        evidence = [
            EvidenceEntry(
                rel_path=rule_rel,
                sha256=sha256_str(rule_content),
                size=len(rule_content.encode("utf-8")),
                provenance={"kind": "cursor-rule", "backup": rule_backup},
            )
        ]
        operations = [
            Operation(rel_path=rule_rel, kind="create", backup=rule_backup)
        ]

        # Optional AGENTS.md fallback only when the target is a project dir.
        if root.name != ".cursor":
            agents_rel = AGENTS_MD_FILENAME
            agents_path = confine(root, Path(agents_rel))
            agents_backup = backup_existing(root, agents_rel)
            atomic_write(agents_path, body.encode("utf-8"))
            evidence.append(
                EvidenceEntry(
                    rel_path=agents_rel,
                    sha256=sha256_str(body),
                    size=len(body.encode("utf-8")),
                    provenance={"kind": "cursor-agents-md", "backup": agents_backup},
                )
            )
            operations.append(
                Operation(rel_path=agents_rel, kind="create", backup=agents_backup)
            )

        return {
            "platform": self.platform,
            "status": "ok",
            "target": str(root),
            "rule_path": str(rule_path),
            "always_apply": True,
            "artifacts": [
                {"path": op.rel_path, "kind": op.kind, "backup": op.backup}
                for op in operations
            ],
        }

    def restore(self, target: Path | None = None) -> Mapping[str, Any]:
        raise InstructionDeployError(
            "Cursor restore is not yet wired to a persisted evidence manifest; "
            "reversing requires the recorded .backup snapshot set"
        )


__all__ = ["CursorAdapter", "cursor_default_target"]
