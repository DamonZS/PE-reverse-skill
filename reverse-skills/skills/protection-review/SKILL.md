---
name: protection-review
description: Authorization-gated review planning for license controls, integrity checks, anti-tamper mechanisms, and anti-cheat protections.
---

# Protection Mechanism Review

Use this workflow for an authorized review of a product's license checks,
integrity controls, anti-tamper features, or anti-cheat architecture. It
produces a static evidence plan and never turns a review request into a bypass
or modification action.

## Workflow

1. Record the product owner, scope, artifact identity, and explicit review
   authorization in the case record.
2. Map license, integrity, and anti-cheat components from supplied local
   artifacts, configuration, logs, and documented interfaces.
3. Classify checks by purpose, data source, failure mode, and evidence path.
4. Offer `anti_tamper_lab` only as an authorization-gated capability candidate;
   the router does not resolve or invoke providers.
5. Produce findings about resilience, compatibility, false-positive risk, and
   observability with evidence links and remediation-oriented recommendations.

## Boundary

- No license bypass, key generation, binary patching, injection, or cheat
  evasion is part of this workflow.
- Do not execute a protected client or modify original artifacts.
- Any controlled experiment must use an explicit, separately authorized
  capability operation.

