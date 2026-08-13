# Case Scope

## meta
- case_id: ctf-demo
- created: 2026-08-02T00:00:00.0000000+08:00
- operator: local
- primary_skill: pwn-chain/SKILL.md
- primary_id: R17
- lead_role: lead
- specialist_roles: [pwn-specialist]
- hint: CTF pwn 栈溢出 gets

## auth
- status: granted
- basis: ctf_lab (CTF 靶场授权)
- evidence_of_auth: 平台授权条款（靶场挑战自带授权）
- MUST NOT proceed if status != granted

## in_scope
- assets:
  - https://ctf.example.com/challenges/pwn1
- surfaces: [binary download, remote service]
- activities: [static analysis, exploit development, remote verification]

## out_of_scope
- assets: [其他挑战、平台基础设施]
- activities: [dos, phishing_real_users, unrestricted_exfil]

## network_profile
- mode: authorized_target_only
- notes: |
    offline | lab_only | authorized_target_only | unrestricted_lab
    Change mode only after auth.status = granted.

## deliverables
- report: true
- field_journal: true
- diagrams: true
- timeline: true

## constraints
- timebox: {2h}
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
