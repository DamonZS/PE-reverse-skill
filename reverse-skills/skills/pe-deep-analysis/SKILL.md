---
name: pe-deep-analysis
description: Perform deeper local, offline PE reasoning from collected static evidence. Use for control-flow maps, data-flow tracing, decoder reconstruction, API-use interpretation, and bounded disassembly review without executing the target.
---

# PE Deep Analysis

1. State the question, evidence boundary, and confidence before tracing code or data flow.
2. Build small, reviewable control-flow and data-flow claims tied to addresses, functions, or artifact references.
3. Separate observed instructions from inferred behavior and record alternative explanations.
4. Do not execute, emulate, debug, patch, inject into, or network-enable the target.
5. Route stable behavior models to `source-reconstruction`; use `case-review` to challenge unsupported conclusions.
