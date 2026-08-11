# Case Scope

## meta
- case_id: intelligent-router-implementation
- created: 2026-08-11T23:41:27.6022307+08:00
- operator: local
- project_root: D:\Project\PE-reverse-skill
- primary_skill: reverse-engineering/SKILL.md
- primary_id: R0
- lead_role: lead
- specialist_roles: [cae, doc]
- hint: 将本项目做成由主技能开始的智能逆向任务路由器，按接口、网址、包和保护类别选择流程，并自动索引子技能和工具；仅修改本项目代码与文档。

## auth
- status: granted
- basis: own_system
- evidence_of_auth: cli-flag AuthGranted or AuthStatus=granted
- MUST NOT proceed if status != granted

## in_scope
- assets: [source_repository, routing_configuration, local_python_tests]
- surfaces: [skill_router_runtime, skill_metadata, generated_navigation, local_cli]
- activities: [local_code_review, local_configuration_update, local_test_execution, documentation_update]

## out_of_scope
- assets: []
- activities: [dos, phishing_real_users, unrestricted_exfil, target_execution, remote_endpoint_fetch, tool_installation, bypass_or_evasion_execution]

## network_profile
- mode: offline
- notes: |
    offline | lab_only | authorized_target_only | unrestricted_lab
    Change mode only after auth.status = granted.

## deliverables
- report: true
- field_journal: true
- diagrams: true
- timeline: true

## constraints
- timebox: {}
- stealth: low
- data_handling: anonymize

## signoff
- ready_for_act: true
- checklist:
  - [x] auth.status = granted
  - [x] in_scope.assets non-empty OR offline sample path set
  - [x] network_profile.mode chosen
  - [x] out_of_scope reviewed
  - [x] roles assigned (see skills/ops/role-map.md)

## ops_refs
- skills/ops/scope-contract.md
- skills/ops/evidence-finding-path.md
- skills/ops/role-map.md
- skills/ops/timeline-workitem.md
- skills/ops/IDENTITY.md
