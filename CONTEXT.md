# Context

This repository provides evidence-backed reverse-analysis tooling for files and
targets the operator is authorized to inspect. The checked-in skill suite is a
planning layer over the existing Python analyzer.

## Vocabulary

- **Case**: A local, isolated analysis workspace with scope, evidence, timeline,
  work-item, and report artifacts.
- **Plan**: A deterministic route and proposed next actions.
- **Skill**: A concise instruction package with optional local helper scripts,
  references, and declared tool requirements.
- **Tool index**: A generated record of locally discoverable tools and their
  readiness.
- **Evidence**: A file or structured observation tied to a case and verified by
  a SHA-256 digest where appropriate.

## Cross-platform instruction deployment

`reverse_analyzer/instructions/` injects a single branded "拓扑" ("topo") break-out
instruction bundle into the four major AI coding clients. Terms used there:

- **Instruction profile**: the platform-agnostic instruction bundle name
  (`topo-ac-unrestricted`); the main munition content is reused from
  `gpt5.5-unrestricted.md`.
- **Platform adapter**: one of `CodexAdapter` / `ClaudeAdapter` / `CursorAdapter` /
  `WorkBuddyAdapter`, each implementing `deploy` / `inspect` / `restore` /
  `describe` / `default_target`.
- **DeployPlan / Operation / EvidenceEntry**: the read-only plan description and
  the per-write evidence record (relative path, SHA-256, provenance, backup).
- **Activation word**: a branded token (拓扑 / AC) that flips the client into the
  unbounded research mode; detection tracks both the branded and historical
  `Leila` tokens (dual-track).
- **reverse-instruct**: the CLI entry (`reverse_analyzer/instructions/cli.py`)
  that routes `list` / `describe` / `inspect` / `deploy` / `restore`.

Deployment is gated by `allowed=True` (or `force`); `dry_run` is a zero-side-effect
preview and needs no authorization. Every write is confined to the target root via
`confine`, written atomically, and backed up for reversal.
