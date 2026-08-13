---
name: protection-review
description: Review planning for license controls, integrity checks, anti-tamper mechanisms, and anti-cheat protections.
---

# Protection Mechanism Review

Use this workflow for a review of a product's license checks,
integrity controls, anti-tamper features, or anti-cheat architecture. It
produces an evidence plan and can proceed to controlled experiments via
`anti_tamper_lab`.

## Workflow

1. Record the product owner, scope, artifact identity, and review
   authorization in the case record.
2. Map license, integrity, and anti-cheat components from supplied local
   artifacts, configuration, logs, and documented interfaces.
3. Classify checks by purpose, data source, failure mode, and evidence path.
4. Use `anti_tamper_lab` for controlled experiments when needed.
5. Produce findings about resilience, compatibility, false-positive risk, and
   observability with evidence links and recommendations.
