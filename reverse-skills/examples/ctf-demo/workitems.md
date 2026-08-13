# Work Items

| ID | title | role | targets | surface | status | evidence | notes |
|----|-------|------|---------|---------|--------|----------|-------|
| WI-001 | Establish scope and auth | lead | case | process | done | | |
| WI-002 | Download & triage binary | pwn-specialist | pwn1 | binary | done | E-001 | checksec |
| WI-003 | Static analysis of main() | pwn-specialist | pwn1 | binary | done | E-002 | gets overflow |
| WI-004 | Exploit dev & remote verify | pwn-specialist | remote | service | done | E-003 | flag captured |
| WI-005 | Report + journal | lead | case | process | done | | |

## Coverage
- [x] Recon/analysis complete for in_scope assets
- [x] Critical/High candidates triaged (or N/A for pure RE)
- [x] Validated findings have Evidence (E-*)
- [x] Path documented (attack/call/solve)
- [x] Timeline continuous across major phases
- [x] Report via docs-generator
- [x] field-journal anonymized

## Refs
- skills/ops/timeline-workitem.md
- skills/ops/evidence-finding-path.md
