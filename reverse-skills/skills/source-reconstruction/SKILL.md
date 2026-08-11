---
name: source-reconstruction
description: Reconstruct evidence-labeled pseudocode and program structure from PE analysis records. Use when translating static observations into functions, types, data models, module boundaries, or human-readable behavior without claiming unavailable source code.
---

# Source Reconstruction

1. Reconstruct only what the collected evidence supports; label hypotheses and unknowns explicitly.
2. Preserve links from pseudocode, names, types, and constants back to their supporting observations.
3. Prefer small modules and function summaries over speculative whole-program rewrites.
4. Do not produce a claim of original source recovery, execute the target, or seek outside enrichment.
5. Submit the reconstruction to `case-review` before presenting it as a case conclusion.
