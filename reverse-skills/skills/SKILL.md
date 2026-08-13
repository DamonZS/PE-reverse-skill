---
name: pe-skill-workbench
description: Master-first, configuration-driven reverse-analysis routing for local files, endpoint descriptors, interfaces, package ecosystems, and protection reviews. It returns an evidence-oriented workflow with indexed subskills and local helper tools.
---

# Intelligent Reverse Task Router

This is the AI entry point for the checked-in skill suite. Start here, then let
`config/routing.json` choose one workflow. The route result is a plan: it
includes the master skill, ordered workflow stages, related subskills, and
declared local helper tools.

`config/routing.json` is the routing source of truth.
`config/tool-manifest.json` is the helper-tool contract.
`INDEX.md` is generated navigation, not a second routing implementation.
`ops/IDENTITY.md` defines the case and reporting identity contract used by the suite.

## Master Route

Route every request through the master entry before opening a workflow skill:

```powershell
python scripts/master-route.py --intent "<request>" --target "<local-path>"
```

Use structured descriptors when the task is about a supplied interface, URL,
or package ecosystem.

```powershell
python scripts/master-route.py --intent "inspect interface" --endpoint "https://api.example.test/openapi.json" --interface rest --package openapi
```

The installed analyzer exposes the same plan:

```powershell
python -m reverse_analyzer skills --root "<reverse-skills-root>" route "<request>" --target "<local-path>"
```

After routing:

1. Read the returned master `SKILL.md`, then the ordered workflow stages.
2. Use the returned subskills and tool records as an index.
3. Create a local case workspace before writing findings:

   ```powershell
   python scripts/case-init.py --case-dir "<case-directory>"
   ```

4. Validate and regenerate navigation after changing the configuration or a skill:

   ```powershell
   python scripts/refresh-skill-index.py
   python scripts/verify-skill-suite.py --strict-index
   ```

## Workflow Families

| Input or intent | Primary workflow | Routed subskills and tools |
| --- | --- | --- |
| Local PE/EXE/DLL/SYS | `pe-triage` and PE stages | PE evidence, reconstruction, case review |
| URL, OpenAPI, HAR, GraphQL, WebSocket, gRPC | `interface-analysis` | API/JS review and local case tools |
| APK/AAB or Android descriptor | `apk-reverse` | static reverse engineering and case review |
| IPA/app or iOS descriptor | `mobile-reverse` | mobile/reverse references and case review |
| .NET/CLR/NuGet descriptor | `dotnet-analysis` | PE stages, reconstruction, case review |
| JAR/ASAR/npm/Python/archive package | `package-analysis` | package analysis, reconstruction, case review |
| License, integrity, anti-tamper, anti-cheat | `protection-review` | evidence review and `anti_tamper_lab` |
| EDR, endpoint telemetry, detection coverage | `edr-defense-review` | defensive static analysis and case review |
