---
name: edr-defense-review
description: Authorization-gated defensive review planning for endpoint-protection hooks, telemetry coverage, and detection evidence.
---

# EDR and Endpoint Telemetry Defense Review

Use this workflow to assess endpoint-protection telemetry, local detection
coverage, and compatibility evidence for an authorized product or lab. The
local source suite at `H:\xunlei\reverse-skill-main\reverse-skill-main\skills\edr-bypass-re`
is treated as research lineage only; this workflow does not automatically
invoke bypass, disable, unhook, injection, or evasion behavior.

## Workflow

1. Record the authorized endpoint product, version, sample identity, and review
   objective in the case scope.
2. Inventory supplied local binaries, logs, configurations, and telemetry
   descriptors.
3. Map observed hooks, providers, event sources, and detection signals to the
   corresponding evidence artifacts.
4. Identify coverage gaps, compatibility concerns, false positives, and
   investigation constraints without modifying endpoint protection.
5. Produce an evidence-backed defensive report and hand off any controlled lab
   validation to an explicit authorization-gated capability operation.

## Boundary

- Do not patch AMSI or ETW, unhook libraries, inject code, disable telemetry,
  or bypass endpoint protection.
- Do not attach to a process, communicate with a production endpoint, or run a
  sample from this workflow.
- Keep the route output to planning, local documentation, and evidence index.

