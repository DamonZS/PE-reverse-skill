---
name: pe-static-analysis
description: Analyze PE structure with local, offline static methods. Use for DOS and NT headers, sections, data directories, imports, exports, resources, strings, compiler clues, and static indicators without executing a target.
---

# PE Static Analysis

1. Begin from a triage case and preserve each observation with its source and confidence.
2. Inspect headers, sections, directories, imports, exports, resources, and strings with approved local tools already available in the environment.
3. Treat packer, compiler, and maliciousness labels as hypotheses until supporting evidence is recorded.
4. Do not run the target, attach a debugger, contact external services, or install tools.
5. Route control-flow or decoder questions to `pe-deep-analysis`, and route readable behavior models to `source-reconstruction`.
