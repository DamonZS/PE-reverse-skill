# PE Reverse Analyzer

A local-first platform for authorized reverse engineering and software-security research. It organizes static analysis, dynamic evidence, audited runtime capabilities, PE/APK workflows, protocol inference, source/GUI project skeletons, Semantic IR, evidence manifests, and the Dashboard into traceable analysis sessions.

[中文](README.md) · [English](README.en.md) · [Project Knowledge Graph](docs/项目知识图谱.md) · [License](LICENSE)

> The Chinese README is the default GitHub document. This edition describes current CLI and provider behavior only; options accepted by the CLI but not yet connected to a real provider are called out explicitly.

## Capability Overview

| Entry point | Current implementation |
|---|---|
| `analyze` | File metadata, hashes, strings, PE/APK/IPA static evidence, entropy/packer heuristics, YARA, optional Ghidra/Frida/Procmon, GUI evidence, Semantic IR, and reports. |
| `capability` | A common `supports -> plan -> validate -> execute -> rollback -> collect_artifacts` provider lifecycle, audit records, and mock providers. |
| `memory` | Windows process-memory scan/read, precondition-bound writes, protection changes, allocation, free, controlled DLL injection, and a Frida hook-trace interface. |
| `patch` | PE patch planning, fail-closed verification, writing a new patched copy, and rolling back to another new copy. `inline_patch` is the currently reliable end-to-end CLI path. |
| `android` | APK static analysis, bounded unpacking, local ZIP verification/copy, and optional apktool + apksigner rebuilding. |
| `protocol` | Import passive PCAP/PCAPNG/JSON/JSONL/raw evidence, reassemble flows, infer framing and fields, and generate summaries. It is not a live packet capture tool. |
| `source reconstruct` | Generate an editable project skeleton with provenance/confidence from the sample and available evidence. It does not claim complete original-source recovery. |
| `dashboard` | Generate a static Dashboard or use the built-in HTTP server to inspect sessions, capability audits, platform analyses, trends, and artifacts. |
| `environment validate` | Discover optional dependencies and optionally execute bounded import, version, or capability probes, writing `environment-validation.json`. |

The platform does not automatically upload samples, reports, keys, or traces. Analysis depth depends on the sample type, operating system, target permissions, and locally available optional tooling.

## Quick Start

### Environment

- Python 3.10+
- Core dependencies in `requirements.txt`: `pefile`, `capstone`, and `requests`
- PowerShell is recommended on Windows; Linux/macOS can run local workflows that do not depend on Win32 providers

```powershell
python -m pip install -r requirements.txt
python -m reverse_analyzer --help
python -m reverse_analyzer list-tools
python -m reverse_analyzer capability list
```

Discover optional dependencies, or explicitly execute bounded probes:

```powershell
# Discover dependencies without executing probes
python -m reverse_analyzer environment validate --out .\out

# Execute bounded import, version, or capability probes for discovered dependencies
python -m reverse_analyzer environment validate --execute-probes --out .\out
```

`environment-validation.json` records dependency discovery separately from probe verification:

- `discovered`: the dependency was found, but no successful executed probe is available.
- `verified`: a bounded probe executed successfully. This is not complete E2E validation against a real sample, device, or live target.
- `dependency-gated`: the display form of the JSON machine value `dependency_gated`. A production path exists, but probe, external runtime/toolchain, or live-target E2E evidence remains open.

Initialize local knowledge storage and run a baseline analysis:

```powershell
python -m reverse_analyzer init-knowledge
python -m reverse_analyzer analyze .\sample.exe --out .\out --max-iterations 3
```

Typical top-level artifacts:

```text
out/
  report.json
  report.md
  trace.jsonl
  analysis_graph.json
  semantic_ir.json
  evidence-manifest.json
  sessions/
```

### Result Status

| Status | Meaning |
|---|---|
| `unavailable` | The current platform or an optional tool cannot satisfy execution requirements. The affected stage normally stops before side effects while preserving structured audit and report output. |
| `partial` | Valid results exist, but a deep parser or optional dependency was unavailable. |
| `failed` | Parameters, permissions, hashes, preconditions, or verification actually failed. These errors are not disguised as graceful `unavailable` results. |

## Main Analysis Pipeline

Baseline static analysis, local rules, and optional Ghidra:

```powershell
python -m reverse_analyzer analyze .\sample.exe --out .\out
python -m reverse_analyzer analyze .\sample.exe --out .\out --decompile --ghidra-home C:\ghidra
```

Optional dynamic evidence and GUI analysis:

```powershell
python -m reverse_analyzer analyze .\sample.exe --out .\out `
  --dynamic --dynamic-backend frida --dynamic-profile auto

python -m reverse_analyzer analyze .\sample.exe --out .\out `
  --gui --gui-runtime --gui-visual --reconstruct-gui
```

- Dynamic profiles include `quick`, `behavior`, `unpacking`, `network`, `persistence`, and `auto`; missing Frida/Procmon dependencies produce an explanatory result for the affected stage.
- GUI paths cover WPF, WinForms, Win32, MFC, Qt, Electron, PyInstaller with PyQt/PySide, Delphi/VCL, Android XML/Compose, Flutter, React Native, UIKit/SwiftUI, Unity, WebView Hybrid, and a conservative fallback.
- `--memory-analysis` is the analysis pipeline's bounded, read-only snapshot/diff/RVA-mapping feature. It is separate from the side-effecting `memory` capability CLI documented below.
- `--reconstruct` and `--reconstruct-gui` validate only generated text, structure, and metadata; they do not build or launch a generated project.

Verify an evidence manifest offline:

```powershell
python -m reverse_analyzer evidence verify --manifest .\out\evidence-manifest.json
```

The manifest uses relative artifact paths and records size, SHA-256, and provenance so missing, modified, or escaping paths can be detected.

## Capability Provider Framework

Every capability provider follows this lifecycle:

```text
supports -> plan -> validate -> execute -> rollback -> collect_artifacts
```

Current registry:

| Capability | Real provider | Mock |
|---|---|---|
| `memory_runtime` | `windows_memory_runtime` | `mock` |
| `injector` | `windows_controlled_injector` | `mock` |
| `hook_runtime` | `frida_hook_runtime` | `mock` |
| `patch_executor` | `local_verified_patch` | `mock` |
| `android_rebuild` | `local_android_rebuild` | `mock` |

```powershell
# Show the registry
python -m reverse_analyzer capability list

# Generic execution entry point
python -m reverse_analyzer capability run `
  --capability memory_runtime `
  --action read `
  --pid 4242 `
  --out .\capability-out `
  --provider mock `
  --param address=0x7FF600001000 `
  --param size=64

# Read capability audits from a report
python -m reverse_analyzer capability show-audit `
  --report .\capability-out\report.json
```

- The registry prefers the higher-priority real provider by default. Explicitly select `--provider mock` to produce a `mocked` audit and placeholder artifacts without real side effects.
- `--param key=value` is repeatable. Values are decoded as JSON when possible and otherwise retained as strings.
- `--rollback` asks the provider to execute its generated rollback plan after a successful operation, validating reversibility.
- Each run creates a session, `trace.jsonl`, `report.json`, `report.md`, an evidence manifest, and a capability audit such as `capabilities/memory_runtime_scan_audit.json`.
- The provider interface standardizes lifecycle and auditing; it does not guarantee execution on every platform. Missing dependencies, unsupported platforms, and explicitly unimplemented provider actions return structured `unavailable` results.

## Runtime Memory, Injection, and Hooks

### Memory CLI

```text
memory {scan,read,write,protect,alloc,free,inject,hook-trace}
```

The real memory provider is `windows_memory_runtime`, which calls Win32 APIs through `ctypes`. It executes only on Windows; other platforms return `unavailable` without modifying a target.

Read-only operations:

```powershell
# The current real scan path uses a hexadecimal AOB
python -m reverse_analyzer memory scan `
  --pid 4242 --out .\memory-scan `
  --pattern "4D 5A" --pattern-type aob

python -m reverse_analyzer memory read `
  --pid 4242 --out .\memory-read `
  --address 0x7FF600001000 --size 256
```

Reversible write, protection, and allocation examples. Here, `--rollback` immediately attempts rollback after the operation:

```powershell
python -m reverse_analyzer memory write `
  --pid 4242 --out .\memory-write `
  --address 0x7FF600001000 `
  --data "90 90" --encoding hex --expected "74 05" `
  --rollback

python -m reverse_analyzer memory protect `
  --pid 4242 --out .\memory-protect `
  --address 0x7FF600001000 --size 4096 `
  --protection PAGE_READWRITE --rollback

python -m reverse_analyzer memory alloc `
  --pid 4242 --out .\memory-alloc `
  --size 4096 --protection PAGE_READWRITE --rollback
```

Free requires the exact allocation base. The provider validates the allocation and captures all data needed for rollback first:

```powershell
python -m reverse_analyzer memory free `
  --pid 4242 --out .\memory-free `
  --address 0x000001ABC0000000 --size 4096
```

Current boundaries:

| Command | Current real behavior and limits |
|---|---|
| `scan` | Defaults to at most 256 MiB scanned and 256 results. The CLI accepts `aob/ascii/utf16/pointer`, but the current real provider does not convert the latter three labels; it parses `--pattern` only as a hexadecimal AOB. The provider requires a pattern even though argparse does not. |
| `read` | The default read limit is 16 MiB, with bounded evidence persisted. |
| `write` | The provider currently treats both `--data` and `--expected` as hexadecimal regardless of the other exposed encodings. Real execution requires `--expected`, and preimage/replacement lengths must match. |
| `protect` | The range must fit completely inside one committed region. The CLI forwards `--expected-protection`, but the provider does not currently consume it; it independently records the live protection and precondition hash. |
| `alloc` | The provider accepts Win32 `PAGE_*` names or positive integers. The CLI default `rw` is not currently accepted by the real provider, so pass `PAGE_READWRITE` or another explicit value. |
| `free` | Only an exact allocation base in one readable, committed, private allocation is accepted. Execution is refused if the provider cannot capture complete rollback data. |

The lower-level `probe`, `regions`, and `modules` actions are also implemented but have no dedicated memory subcommand. Invoke them through `capability run --capability memory_runtime --action ...`.

### Controlled DLL Injection

```powershell
python -m reverse_analyzer memory inject `
  --pid 4242 --out .\inject-out `
  --dll C:\lab\trace.dll `
  --method load_library `
  --expected-sha256 <dll-sha256> `
  --rollback
```

- `windows_controlled_injector` currently executes only the Windows `LoadLibraryW` path.
- The DLL path must be absolute. `--expected-sha256` can bind the plan to a specific payload.
- Rollback attempts remote `FreeLibrary`, frees temporary memory, and checks that the module disappeared. Additional references in the target can prevent a complete unload.
- `manual_map` now has controlled Win32 execute and rollback paths covering PE32/PE32+ mapping, relocations, normal and delay imports, TLS callbacks, x64 exception tables, section protections, entry-point invocation, and reverse-order cleanup. Ordinary regression tests use deterministic host fixtures; a gated E2E against a real Windows target is still required.

### Hook Trace

The real hook provider is `frida_hook_runtime`, with `api_hook`, `inline_hook`, and `breakpoint_trace` actions. It depends on the optional Python `frida` binding/runtime, accepts data-driven hook specifications only, and rejects arbitrary JavaScript. A plan can still be generated without Frida, while execution returns `unavailable`.

The currently executable interface is the generic capability command:

```powershell
python -m reverse_analyzer capability run `
  --capability hook_runtime `
  --action api_hook `
  --pid 4242 `
  --out .\hook-out `
  --provider frida_hook_runtime `
  --param 'hook_specification={"type":"api_hook","module":"kernel32.dll","export":"CreateFileW"}' `
  --param duration_ms=10000
```

The `memory hook-trace --plan ... --duration ... --backend ...` convenience command is registered, but its adapter currently forwards `plan_path`/`duration`/`backend` while the provider reads `hook_specification`/`duration_ms`. It does not load the plan file or use that backend argument yet, so the convenience command is not a connected real hook-execution path.

## PE Patch: plan / verify / apply / rollback

The currently reliable CLI workflow is an equal-length `inline_patch`:

```powershell
python -m reverse_analyzer patch plan .\sample.exe `
  --out .\patch-session `
  --strategy inline_patch `
  --offset 0x120 `
  --replacement "90 90" `
  --operation-id replace-branch

python -m reverse_analyzer patch verify .\sample.exe `
  --plan .\patch-session\patch\plan.json `
  --out .\patch-session\patch

python -m reverse_analyzer patch apply .\sample.exe `
  --plan .\patch-session\patch\plan.json `
  --out .\patched.exe `
  --artifact-dir .\patch-session\patch

python -m reverse_analyzer patch rollback .\patched.exe `
  --plan .\patch-session\patch\rollback_plan.json `
  --out .\restored.exe `
  --artifact-dir .\patch-session\patch
```

- `patch plan --out X` writes artifacts under `X/patch/`. Typical files are `plan.json`, `verify.json`, `risk_report.json`, and `rollback_plan.json`.
- The input PE is always read-only. Apply and rollback require different paths and write new files. Apply re-verifies before writing, and the rollback plan binds the patched SHA-256.
- Verification fails closed on target hash, preimage, PE layout, strategy contract, instruction boundaries/CFG, and rollback recoverability. It also reports PE directory, relocation, and overlay risks.
- `auto` currently resolves to `inline_patch`. The parser also accepts `code_cave_patch`, `section_extend_patch`, `resource_replace`, `iat_thunk_patch`, `entrypoint_redirect`, and `overlay_preserve_patch`, but these advanced strategies commonly require intent fields that the current CLI does not expose and are not general end-to-end CLI workflows.
- Missing `pefile` produces `unavailable`. For a patch in an executable section, missing Capstone or a PE machine other than x86 (`0x14c`)/x64 (`0x8664`) makes instruction checking unavailable and the overall verification `failed`.
- Authenticode handling only detects the certificate table and reports that a patch can invalidate a signature. It does not validate the certificate chain or re-sign the file.

The same engine is available through the `patch_executor -> local_verified_patch` capability provider with `plan`, `validate`, `apply`, and `rollback` actions.

## Android: analyze / unpack / rebuild / verify

```powershell
# Complete APK static-analysis pipeline
python -m reverse_analyzer android analyze .\app.apk --out .\android-analysis

# Bounded Python ZIP unpacking is the default
python -m reverse_analyzer android unpack .\app.apk `
  --out .\android-unpack `
  --destination .\decoded

# Default zip_copy: verify, then copy bytes into a new APK
python -m reverse_analyzer android rebuild .\app.apk `
  --out .\android-rebuild `
  --apk-out .\rebuilt.apk `
  --strategy zip_copy

# Local ZIP/manifest verification
python -m reverse_analyzer android verify .\rebuilt.apk `
  --out .\android-verify
```

`apktool_rebuild` needs apktool, apksigner, and valid signing configuration:

```powershell
python -m reverse_analyzer android rebuild .\app.apk `
  --out .\android-rebuild `
  --project-dir .\decoded `
  --apk-out .\rebuilt-signed.apk `
  --strategy apktool_rebuild `
  --apktool C:\Tools\apktool.bat `
  --apksigner C:\Android\build-tools\35.0.0\apksigner.bat `
  --keystore C:\Keys\research.jks `
  --key-alias research
```

Signature verification must be enabled explicitly. Supplying `--apksigner` alone does not run it:

```powershell
python -m reverse_analyzer android verify .\rebuilt-signed.apk `
  --out .\android-verify `
  --apksigner C:\Android\build-tools\35.0.0\apksigner.bat `
  --param verify_signature=true
```

- `android analyze` aliases the complete `analyze` pipeline. The other commands use the `local_android_rebuild` provider.
- `zip_copy` is a verified byte-for-byte copy whose output hash should equal the source APK hash. It is not a decompile-and-rebuild operation.
- Missing apktool/apksigner or signing configuration produces `unavailable` for the external-tool stage. ADB is not required for rebuilding.
- ZIP boundaries are 10,000 entries, 128 MiB per entry, 768 MiB total uncompressed data, and a maximum compression ratio of 1,000.
- The provider records rollback metadata. The dedicated `unpack` CLI does not expose `--rollback`; `rebuild` does.

## Protocol: capture / infer / summarize

```powershell
python -m reverse_analyzer protocol capture .\traffic.pcapng `
  --out .\protocol-out --format auto

python -m reverse_analyzer protocol infer .\messages.jsonl `
  --out .\protocol-infer --format jsonl

python -m reverse_analyzer protocol summarize .\stream.bin `
  --out .\protocol-summary --format raw
```

- All three subcommands currently run the complete pipeline: `protocol_capture -> protocol_infer -> protocol_summarize -> protocol_analyze`. Their names indicate entry intent, not a single isolated stage.
- `capture` imports an existing passive evidence file. It neither opens a network interface nor captures live traffic.
- PCAP, PCAPNG, JSON, JSONL, and raw inputs are supported, including TCP reassembly, bidirectional UDP flows, and length-prefix/delimiter/magic/entropy inference.
- The pipeline recognizes JSON, protobuf shapes, base64, gzip, zlib, and msgpack. `msgpack` is optional; without it, heuristic recognition remains and the limitation is recorded as `partial`/a warning.
- Default bounds are 8 MiB input, 4,096 packets, 1,024 messages, and 256 KiB per message. Adjust them with `--max-bytes`, `--max-packets`, `--max-messages`, and `--max-message-bytes`.
- Output includes capture/flow/field statistics, inference, summary, per-message JSON, a Semantic IR fragment, top-level Semantic IR, an evidence graph, reports, and a manifest.
- A missing source returns structured `unavailable` while still preserving a report and manifest.

## Source Reconstruction

```powershell
python -m reverse_analyzer source reconstruct .\sample.exe `
  --out .\source-out `
  --strategy auto `
  --decompile `
  --gui
```

This command aliases `analyze` with `--reconstruct` forced on. The only current strategy is `auto`, which selects among:

- `unity-csharp`
- `android-kotlin`
- `android-java`
- `electron`
- `pyinstaller-python`
- `csharp`
- `cpp`
- `c`

Output is written under `<out>/reconstructed_<sample>/`. It is an editable project skeleton, not complete source recovery. Reconstructed functions and types use conservative placeholders/TODOs, with provenance and confidence retained for inferred material. The default reconstruction path neither builds nor runs the generated project; local commands run only when the caller explicitly supplies a bounded runtime/behavior validation spec. The input sample remains read-only.

Typical metadata:

```text
analysis/source_reconstruction.json
analysis/project.json
analysis/provenance.json
analysis/confidence.json
analysis/evidence_index.json
analysis/behavior_hints.json
analysis/equivalence_assessment.json
analysis/summary.json
```

`analysis/equivalence_assessment.json` summarizes differential/static/runtime observed evidence and associates each mismatch with Semantic IR and provenance. `matched` means only that the supplied observations met their thresholds; `claim_scope` is fixed to `observed_evidence_only`, and `complete_behavior_equivalence_proven` is always `false`. It does not automatically prove complete source recovery or complete behavior, timing, environment, or state-space equivalence.

## Dashboard

```powershell
# Generate static Dashboard files only
python -m reverse_analyzer dashboard --workspace . --out .\dashboard

# Generate and start the built-in server
python -m reverse_analyzer dashboard --workspace . --out .\dashboard --serve

# Spell out the default bind address and port
python -m reverse_analyzer dashboard --workspace . --out .\dashboard `
  --serve --host 127.0.0.1 --port 8088
```

- Without `--serve`, the command only generates `index.html` and `data.json`.
- The default host is `127.0.0.1`; the default port comes from configuration or is `8088`. `--serve` runs until interrupted.
- `--host` is used directly for binding. Passing a non-loopback address changes the exposure scope.
- Current views aggregate engine/Android/protocol/source analyses, capability audits, KnowledgeBase recommendations, session comparisons and trends, artifact navigation, Semantic IR, evidence graphs, platform-core summaries, and the newest valid workspace `environment-validation.json`.
- The environment panel separates dependency discovery from probe verification and preserves the `discovered`, `verified`, and `dependency_gated` machine states. The source-reconstruction panel shows the observed-evidence assessment, dimensions, and mismatches while explicitly declining a complete-behavior proof claim.

## Dependencies and Platform Limits

| Component | Type | Behavior when missing |
|---|---|---|
| `pefile`, `capstone`, `requests` | Core Python dependencies in `requirements.txt` | The affected function fails or follows the unavailable rules above; executable PE patch verification can fail overall. |
| Ghidra | Optional external tool | Decompilation is `unavailable`; other local analysis continues. |
| Frida Python binding/runtime | Optional | Dynamic collection/hook execution is `unavailable`; plans and static evidence can remain. |
| Procmon | Optional, Windows | The Procmon dynamic collection stage is `unavailable`. |
| `yara-python` | Optional | YARA depth is reduced while other rule/static evidence continues. |
| apktool, apksigner, Android build tools | Optional | `apktool_rebuild` or explicit signature verification is `unavailable`; `zip_copy` and local verification remain available. |
| `msgpack` | Optional | Deep msgpack parsing degrades to heuristic `partial` results. |
| ADB | Optional | It affects other Android/dynamic paths and is not required for APK rebuilding. |
| Xcode, `xcrun`, signing identities, physical iOS devices | Optional, macOS/live target | The environment report can only discover and probe the toolchain. Offline IPA static analysis remains available; rebuild, re-signing, and dynamic-device validation are outside the completed scope. |
| Win32 memory/injector/native-hook/debugger and UIA | Windows, target rights, compatible architecture, interactive desktop | Fake backends and opt-in smokes do not close live-target gates. Missing platform access, rights, `comtypes`, or a visible window leaves the path `dependency-gated`, `partial`, or `unavailable`. |
| PresentMon, graphics bridge, ImGui bridge | Optional, Windows | A probe confirms only that a tool or bridge responds; it does not prove an in-process Present hook, ImGui backend, or real graphics lifecycle E2E. |
| Kernel bridge, signed driver, live IOCTL fixture | External Windows lab stack | `environment-validation.json` can expose dependency state, but the kernel runtime is still `missing`; file discovery or a bridge probe is not a driver E2E. |
| MemProcFS/LeechCore, DMA hardware and acquisition permissions | External hardware/runtime | The DMA provider is still `missing`; an executable probe does not prove hardware initialization, address translation, or live acquisition. |
| `comtypes`, Tesseract, VLM provider | Optional GUI/OCR/model runtime | UIA needs a Windows desktop and real window. VLM/OCR acceptance also needs a non-test provider, real images, and successful requests; mock/plugin discovery does not close validation. |

`windows_memory_runtime` and `windows_controlled_injector` execute only on Windows. Even there, process architecture, target lifetime, access tokens, protected processes, and memory rights can end an operation as `failed`. PE patching, local APK handling, protocol import, reports, and the Dashboard do not inherently require Windows.

The `discovered`, `verified`, and `dependency_gated` states above are environment-readiness evidence only and never promote capability status automatically. See the [Skill Parity Matrix](docs/skill_parity_matrix.md) for per-capability implementation and acceptance boundaries.

## Analysis Model Provider Boundary

Capability providers and analysis-model providers are separate layers:

| Item | Current behavior |
|---|---|
| Default analysis provider | `RuleBasedProvider`: local, deterministic, and network-free. |
| OpenAI-compatible interface | `OpenAICompatibleProvider` is an adapter boundary only. The current `analyze` CLI has no built-in HTTP transport. |
| Remote calls | They are possible only when an application layer explicitly enables the provider and injects a controlled `transport`. Setting API environment variables alone does not upload samples. |

The project does not include model jailbreak, safety-policy bypass, or "unrestricted model" functionality.

## Configuration

| Environment variable | Description |
|---|---|
| `REVERSE_ANALYZER_WORKSPACE` | Workspace root. |
| `REVERSE_ANALYZER_KNOWLEDGE_DIR` | KnowledgeBase directory. |
| `REVERSE_ANALYZER_SESSIONS_DIR` | Session directory. |
| `REVERSE_ANALYZER_REPORTS_DIR` | Report directory. |
| `REVERSE_ANALYZER_DASHBOARD_PORT` | Dashboard port; defaults to `8088`. |
| `GHIDRA_HOME` | Ghidra root; `--ghidra-home` overrides it. |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `OPENAI_MODEL` | OpenAI-compatible provider instance settings; they do not mean that the CLI has a remote transport. |
| `REVERSE_ANALYZER_OPENAI_ENABLED` | Explicit remote switch for a provider instance; the caller must still provide a transport. |

## Development Verification

```powershell
python -m compileall reverse_analyzer tests
python -m unittest discover -s tests -v
git diff --check
```

Use this project only with software you own, publicly licensed samples, CTF targets, or software covered by explicit authorization. Use is governed by [LICENSE](LICENSE).
