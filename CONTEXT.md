# Context

This repository provides evidence-backed reverse-analysis tooling for files and
targets the operator is authorized to inspect. The checked-in skill suite is a
planning layer over the existing Python analyzer; it does not itself execute a
target or install dependencies.

## Vocabulary

- **Case**: A local, isolated analysis workspace with scope, evidence, timeline,
  work-item, and report artifacts.
- **Plan**: A deterministic route and proposed next actions. A plan grants no
  permission to execute software, attach to a process, contact a service, or
  modify a binary.
- **Skill**: A concise instruction package with optional local helper scripts,
  references, and declared tool requirements.
- **Tool index**: A generated record of locally discoverable tools and their
  readiness. Missing tools are reported, never installed automatically.
- **Evidence**: A file or structured observation tied to a case and verified by
  a SHA-256 digest where appropriate.

## Scope Boundary

Default work is offline static inspection of a supplied local file. Dynamic
analysis, process attachment, device interaction, network access, and output
binary modification require explicit authorization and an intentional command
outside the routing layer.
