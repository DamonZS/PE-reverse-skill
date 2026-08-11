---
name: pe-triage
description: Perform a local, offline first-pass intake of a PE file or PE analysis case. Use for headers, basic metadata, hashes, imports, sections, and an evidence-first scope statement without running the target.
---

# PE Triage

1. Create an empty local case with `python scripts/case-init.py --case-dir <case-dir>`.
2. Route ambiguous requests with `python scripts/master-route.py --intent "<request>"`.
3. Record the target's provenance, hash, architecture, header observations, and unresolved questions as evidence.
4. Use only already-installed local static tools. Do not execute the target, open network connections, or install dependencies.
5. Hand structural questions to `pe-static-analysis`; close the intake with `case-review` when no deeper analysis is needed.
