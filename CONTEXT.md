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
