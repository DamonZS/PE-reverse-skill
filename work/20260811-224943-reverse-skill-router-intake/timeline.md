# Timeline (append-only)

## 2026-08-11T22:49:44.1785058+08:00 | lead | init
- action: case-init
- command_or_ref: skills/scripts/case-init.ps1
- result_summary: case directory created; scope pending auth
- artifacts: [scope.md, workitems.md]
- evidence_ids: []
- next: fill scope auth + in_scope; set ready_for_act

## 2026-08-11T22:51:06.0496930+08:00 | lead | routing
- action: routed reverse-skill-router invocation without a target
- command_or_ref: skills/MASTER-ROUTING.md; skills/scripts/case-init.ps1
- result_summary: R0 selected by fallback; cre assigned; no in-scope asset or analysis objective supplied
- artifacts: [scope.md, workitems.md]
- evidence_ids: []
- next: collect a target and intended analysis outcome before triage
