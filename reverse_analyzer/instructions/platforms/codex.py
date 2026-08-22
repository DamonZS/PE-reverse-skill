"""Codex platform adapter.

Defers the real deployment to the mature ``reverse_analyzer.codex`` backend
(inject / inspect / restore), and exposes it through the uniform
``PlatformAdapter`` interface.  This is the reference implementation for the
cross-platform instruction-deploy framework: it already ships a tuned
``config.toml`` ``model_instructions_file`` writer plus evidence manifest and
backup/rollback, so we reuse it verbatim.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..adapter import (
    DeployPlan,
    IDENTITY_WORD,
    INSTRUCTION_PROFILE,
    InstructionDeployError,
    Operation,
    PLATFORM_CODEX,
    PlatformAdapter,
)

CONFIG_FILENAME = "config.toml"
MODEL_INSTRUCTIONS_KEY = "model_instructions_file"
INSTRUCTION_ASSET = "gpt5.5-unrestricted.md"


def codex_default_target() -> Path:
    """Return the conventional ~/.codex config root."""
    return Path("~/.codex").expanduser()


class CodexAdapter(PlatformAdapter):
    platform = PLATFORM_CODEX

    def default_target(self) -> Path:
        return codex_default_target()

    def describe(self, target: Path | None = None) -> DeployPlan:
        deployment_target = (target or self.default_target()).expanduser().resolve()
        config_path = deployment_target / CONFIG_FILENAME
        notes = []
        if not config_path.is_file():
            notes.append(
                f"target lacks {CONFIG_FILENAME}; deploy requires --force "
                "or an existing config.toml"
            )
        else:
            notes.append(
                f"will rewrite {MODEL_INSTRUCTIONS_KEY} -> ./{INSTRUCTION_ASSET}"
            )
        return DeployPlan(
            platform=self.platform,
            target=str(deployment_target),
            operations=(
                Operation(
                    rel_path=INSTRUCTION_ASSET,
                    kind="create",
                    description="branded global instruction file (topo identity)",
                ),
                Operation(
                    rel_path="skills/ac/SKILL.md",
                    kind="create",
                    description="AC unlimited router skill",
                ),
                Operation(
                    rel_path="skills/ac/references/router-contract.md",
                    kind="create",
                    description="router state-machine reference",
                ),
                Operation(
                    rel_path="skills/ac/references/unrestricted-lab.md",
                    kind="create",
                    description="unrestricted lab reference",
                ),
                Operation(
                    rel_path="skills/ac/agents/openai.yaml",
                    kind="create",
                    description="AC skill agent descriptor",
                ),
                Operation(
                    rel_path="skills/topo-identity/SKILL.md",
                    kind="create",
                    description="topo identity skill",
                ),
                Operation(
                    rel_path="skills/topo-identity/agents/openai.yaml",
                    kind="create",
                    description="topo-identity agent descriptor",
                ),
            ),
            notes=tuple(notes),
        )

    def inspect(self, target: Path | None = None) -> Mapping[str, Any]:
        from reverse_analyzer.codex.inspect import inspect_codex

        inner = inspect_codex(target).to_dict()
        # Wrap with the uniform outer contract shared by all adapters.
        return {"platform": self.platform, **inner}

    def deploy(
        self,
        target: Path | None = None,
        *,
        allowed: bool = False,
        force: bool = False,
        dry_run: bool = False,
        instruction_profile: str = INSTRUCTION_PROFILE,
    ) -> Mapping[str, Any]:
        from reverse_analyzer.codex.inject import CodexInjectError, inject_codex, resolve_codex_root

        # dry-run is a zero-side-effect preview: it must not require --allowed.
        if dry_run:
            return {
                "platform": self.platform,
                "status": "dry-run",
                "plan": self.describe(target).to_dict(),
            }

        deployment_target = target or resolve_codex_root()
        try:
            result = inject_codex(
                deployment_target,
                instruction_profile=instruction_profile,
                allowed=allowed,
                unrestricted=force,
                dry_run=dry_run,
            )
        except CodexInjectError as exc:
            raise InstructionDeployError(str(exc)) from exc
        return {
            "platform": self.platform,
            **result,
        }

    def restore(self, target: Path | None = None) -> Mapping[str, Any]:
        from reverse_analyzer.codex.inject import CodexInjectError, restore_codex, resolve_codex_root

        deployment_target = target or resolve_codex_root()
        try:
            result = restore_codex(deployment_target)
        except CodexInjectError as exc:
            raise InstructionDeployError(str(exc)) from exc
        return {
            "platform": self.platform,
            **result,
        }


__all__ = ["CodexAdapter", "codex_default_target"]
