---
name: dotnet-analysis
description: Plan offline CLR, C#, and NuGet analysis with evidence-backed managed-assembly classification and reconstruction.
---

# .NET Package and Assembly Analysis

Use this workflow for a supplied CLR assembly, NuGet package, or managed PE
candidate. It adapts the classification concepts from the local source skill
suite at `H:\xunlei\reverse-skill-main\reverse-skill-main\skills\dotnet-reverse`
without automatically invoking deobfuscation, debugging, or patching tools.

## Workflow

1. Identify CLR metadata, managed entry points, and assembly relationships from
   offline headers and strings.
2. Classify likely protection or obfuscation markers as observations rather
   than modifying the artifact.
3. Record type, method, resource, configuration, and dependency evidence.
4. Use the PE triage, static-analysis, and source-reconstruction stages to
   produce clearly labeled reconstruction notes.
5. Escalate any device, process, debugger, or patch action to an explicit
   authorization-gated operation outside the router.

## Boundary

- Preserve the original assembly and package bytes.
- Do not run, patch, re-sign, load, or inject into the assembly.
- Do not download NuGet dependencies or contact package feeds.

