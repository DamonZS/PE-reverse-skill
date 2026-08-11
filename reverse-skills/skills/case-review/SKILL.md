---
name: case-review
description: Review a local PE analysis case for evidence quality, policy compliance, scope, uncertainty, and report readiness. Use before sharing findings or closing a triage, static-analysis, deep-analysis, or source-reconstruction case.
---

# Case Review

1. Run `python scripts/review-case.py --case-dir <case-dir>` before closing a case.
2. Check every conclusion for a local evidence reference, confidence level, and stated limitations.
3. Reject claims that depend on target execution, networking, automatic installation, or unrecorded external data.
4. Keep unresolved questions visible and route them to the appropriate earlier stage.
5. Use `python scripts/verify-skill-suite.py --strict-index` when changing this workbench's metadata.
