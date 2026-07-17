# Domain Docs

This repository uses a single-context domain-documentation layout.

## Before Exploring

When present, read:

- `CONTEXT.md` at the repository root for domain language and concepts.
- Relevant architecture decision records under `docs/adr/`.

If these files do not exist, continue silently. Producer skills create them when concrete terms or decisions need to be documented.

## Expected Layout

```text
/
|-- CONTEXT.md
|-- docs/
|   `-- adr/
`-- reverse_analyzer/
```

## Vocabulary

Use terms defined in `CONTEXT.md` in issue titles, refactoring proposals, hypotheses, tests, and generated documentation. Avoid introducing synonyms that conflict with the glossary.

If a required concept is absent, reconsider whether it is project terminology or record the documentation gap for a producer skill.

## Architecture Decisions

Read ADRs relevant to the area being changed. Explicitly identify any proposed work that conflicts with an existing ADR instead of silently overriding the decision.
