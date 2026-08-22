# Changelog

All notable changes to `reverse-jailbreak` are recorded here. This project uses
Semantic Versioning.

## [Unreleased]

### Added

- Cross-platform instruction deployment framework under
  `reverse_analyzer/instructions/`: a single branded "拓扑" instruction bundle is
  injected into Codex (`config.toml model_instructions_file`), Claude
  (`settings.json hooks.UserPromptSubmit` + `CLAUDE.md`), Cursor
  (`.cursor/rules/*.mdc` alwaysApply), and WorkBuddy (generated skill package).
- `reverse-instruct` CLI with `list` / `describe` / `inspect` / `deploy` /
  `restore`, registered in `pyproject.toml`, plus a shared safety model
  (`allowed`/`force` gating, `dry_run` zero-side-effect preview, path confining,
  atomic writes, and backup-for-reversal).

### Fixed

- Claude adapter: replaced a double-`.claude` path bug (`<root>/.claude/instruction.md`
  became `~/.claude/.claude/instruction.md`) with a flat layout
  (`instruction.md` at root, hook at `hooks/instruction-inject.sh`).
- Claude hook script: rewrote the plpython3 heredoc as pure bash (`cat "$_INSTR"`)
  so it works under a shimmed/sandboxed shell without an external interpreter.
- Cursor adapter: `describe` now reports `AGENTS.md` only when `deploy` would
  write it (non-`.cursor` roots).
- Codex adapter: `describe` now reports all 7 files that `deploy` actually writes.
- WorkBuddy adapter: removed the strong "外挂" guidance word and trailing space
  from the skill description.
- Test harness: `subprocess.run(..., text=True)` no longer decodes Chinese bash
  output with the Windows locale (GBK) encoding — it passes explicit
  `encoding="utf-8"` and `errors="replace"`.

## [0.1.0] - 2026-07-22

### Added

- Standalone `reverse-jailbreak` console entry point with `doctor`, `profiles`,
  `validate`, `run`, `resume`, `report`, `promote`, and `release-verify`.
- Built-in instruction profiles and OpenAI-compatible campaign transport.
- Stable checkpoints, cross-session resume, evidence manifests, semantic judge
  records, and retained-evidence promotion checks.
- Portable wheel bundle with JSON Schema, starter configuration, release notes,
  file hashes, CycloneDX SBOM, and an isolated-install smoke runner.

[0.1.0]: docs/releases/0.1.0.md
