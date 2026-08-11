---
name: package-analysis
description: Plan offline classification of supplied archives and package ecosystems before selecting specialized reverse-engineering subskills.
---

# Generic Package and Archive Analysis

Use this workflow when the artifact is a package or archive whose ecosystem is
not already selected by a more specific route. It covers package descriptors
such as npm, Electron, NuGet, Python wheels, Java archives, and generic ZIP
containers.

## Workflow

1. Record the package file path, hash, size, and declared ecosystem.
2. Inventory archive members and metadata without installing dependencies or
   executing package scripts.
3. Identify embedded binaries, manifests, native modules, bytecode, and source
   assets.
4. Route the relevant local material to `reverse-engineering`,
   `source-reconstruction`, or `case-review` as indexed subskills.
5. Preserve the original package and report only evidence-backed conclusions.

## Boundary

- Do not install, resolve, publish, or execute package contents.
- Do not contact registries or package URLs from this workflow.
- Treat extracted files as copied analysis artifacts, not runnable targets.

