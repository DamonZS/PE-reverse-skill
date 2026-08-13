# Timeline (append-only)

## 2026-08-02T00:00:00.0000000+08:00 | lead | init
- action: case-init
- command_or_ref: skills/scripts/case-init.ps1
- result_summary: case directory created; scope ready_for_act=true
- artifacts: [scope.md, workitems.md]
- evidence_ids: []
- next: open PRIMARY SKILL.md and ACT within scope

## 2026-08-02T00:15:00.0000000+08:00 | pwn-specialist | recon
- action: download & triage binary
- command_or_ref: file pwn1; checksec --file=./pwn1
- result_summary: ELF 64-bit x86-64, no PIE, NX enabled, partial RELRO, no canary on main
- artifacts: [pwn1]
- evidence_ids: [E-001]
- next: static analysis (IDA/Ghidra) → locate vulnerable function

## 2026-08-02T00:40:00.0000000+08:00 | pwn-specialist | static
- action: decompile main, confirm gets() buffer overflow
- command_or_ref: ghidra headless analyze
- result_summary: main uses gets(buf[0x40]); no canary; ret offset = 0x48
- artifacts: [decomp.md]
- evidence_ids: [E-002]
- next: build exploit (ret2win / ROP)

## 2026-08-02T01:10:00.0000000+08:00 | pwn-specialist | exploit
- action: craft payload, remote verify
- command_or_ref: python3 exploit.py REMOTE
- result_summary: flag captured: ctf{example_flag_do_not_use}
- artifacts: [exploit.py, flag.txt]
- evidence_ids: [E-003]
- next: write report + journal

## 2026-08-02T01:30:00.0000000+08:00 | lead | wrap
- action: report via docs-generator; journal anonymized
- result_summary: report + field-journal written
- artifacts: [report/, field-journal entry]
- evidence_ids: []
- next: (done)
