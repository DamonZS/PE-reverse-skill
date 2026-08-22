# Reverse Analysis Report

## Sample Overview

- **Session Id:** 55500ecbf43b43d0a00fae2e25117646
- **Target:** D:\Project\PE-reverse-skill\reverse-analyzer-server.exe
- **Status:** running
- **Created At:** 2026-08-22T04:51:50.340118+00:00
- **Updated At:** 2026-08-22T04:51:53.324534+00:00

## Evidence Integrity

- **Manifest Path:** evidence-manifest.json
- **Manifest ID:** sha256:9fb768069804a2342f0980e3fe3af367146076d9edb4dd86de6ebe79cd57aee5
- **Hash Algorithm:** sha256
- **Covered Files:** 20
- **Unavailable Stages:** 3
- **Status:** ok
- **Verification Command:** `python -m reverse_analyzer evidence verify --manifest evidence-manifest.json`

## Capability Audit

- **Status:** unavailable
No capability audit records recorded.

## Platform Core

- **Status:** partial
- **Semantic IR:** status=partial modules=1 entities=7
- **Evidence Graph:** status=ok nodes=62 edges=94
- **Capability Registry:** status=ok capabilities=23
- **Capability Audit:** status=unavailable records=0

## Tool Trace

1. `file_info` — ok
2. `hash` — ok
3. `strings_extract` — ok
4. `pe_deep_scan` — ok
5. `packer_detect` — ok
6. `section_entropy_scan` — ok
7. `pe_header_scan` — ok
8. `yara_scan` — unavailable
9. `engine_analyze` — ok
10. `android_analyze` — unavailable
11. `protocol_analyze` — ok
12. `gui_behavior_graph` — ok
13. `semantic_ir_build` — partial

## PE Deep Analysis

- **Status:** ok
- **Shell Score:** 100
- **Shell Verdict:** likely_packed
- **Entrypoint Section:** .text
- **Import DLLs:** 1
- **Exported Symbols:** 0
- **Resources:** 0
- **TLS Callbacks:** 0
- **Overlay Present:** no
- **Overlay Size:** 0
- **Section Anomalies:** 8
- **IAT Anomalies:** 0

## YARA

- **Status:** unavailable
- **Rules Path:** D:\Project\PE-reverse-skill\rules\yara
- **Matches:** 0

## Engine Analysis

- **Status:** ok
- **Platform:** windows-pe
- **Engine:** unknown
- **Confidence:** 0.0
- **Evidence:**
  - No independently corroborated engine signal reached the detection threshold
- **Metadata:** managed_assemblies=0 global_metadata=no gameassembly=no
- **Assets:** pak=0 uasset=0 umap=0 scene_like=0
- **Strategy:** generic_engine_fingerprint

## Android Analysis

- **Status:** unavailable
- **Package Type:** unknown
- **Framework:** unknown
- **Framework Confidence:** 0.0
- **Manifest Present:** no
- **Resources:** layouts=0 drawables=0 values=0 assets=0
- **DEX Files:** 0
- **Native Libraries:** 0
- **Strategy:** unknown_static_unpack

## iOS Analysis

- **Status:** unavailable

## Protocol Analysis

- **Status:** ok
- **Probable Flows:** 7
- **Endpoints:**
  - host: B.idata
  - host: B.symtab
  - host: time.DatH
  - host: time.LocH
  - host: time.LocL
  - host: time.UTCL

## Source Reconstruction

- **Status:** unavailable

## Behavior Evidence Graph

- **Status**: ok
- **Nodes**: 0
- **Edges**: 0
- **Linked Handlers:** 0
- **Dynamic Events:** 0

## Semantic IR

- **Status:** partial
- **Schema Version:** 1
- **Entities:** 7
- **Relations:** 0
- **Capabilities:** 2
- **Top Capabilities:**
  - general: confidence=1.0 evidence=14
  - network_protocol: confidence=0.6 evidence=7

## GUI Analysis

- **Status:** unavailable

## Findings

- **[high] Packed or obfuscated PE characteristics**
  - Source: `pe_deep_scan`
  - Detail: shell_score=100 verdict=likely_packed
  - Confidence: 0.95
  - Evidence: entrypoint={"anomaly": null, "rva": 559040, "section": ".text", "section_executable": true, "section_rva": 4096}; section_anomalies={'section': '.xdata', 'entropy': 1.787112262798912, 'raw_size': 512, 'virtual_size': 180, 'reasons': ['raw_size_exceeds_virtual_size']}, {'section': '/19', 'entropy': 7.996339738557158, 'raw_size': 701952, 'virtual_size': 701873, 'reasons': ['high_entropy']}, {'section': '/32', 'entropy': 7.943523387348717, 'raw_size': 149504, 'virtual_size': 149018, 'reasons': ['high_entropy']}; shell_indicators={'kind': 'section', 'section': '.xdata', 'reason': 'raw_size_exceeds_virtual_size', 'weight': 10}, {'kind': 'section', 'section': '/19', 'reason': 'high_entropy', 'weight': 15}, {'kind': 'section', 'section': '/32', 'reason': 'high_entropy', 'weight': 15}
  - Recommendation: Validate whether the sample is packed, then focus manual reversing on the unpacked entry point and import resolution path.
- **[high] Packer indicators detected**
  - Source: `packer_detect`
  - Detail: score=100 indicators=6
  - Confidence: 0.95
  - Evidence: score=100; indicators={'type': 'high_entropy', 'section': '/19', 'entropy': 7.9963}, {'type': 'high_entropy', 'section': '/32', 'entropy': 7.9435}, {'type': 'high_entropy', 'section': '/65', 'entropy': 7.9983}
  - Recommendation: Inspect unpacking behavior and confirm whether imports or control flow are reconstructed at runtime.
- **[medium] High entropy section or chunk**
  - Source: `section_entropy_scan`
  - Detail: max_entropy=7.998323285349334
  - Confidence: 0.70
  - Evidence: max_entropy=7.998323285349334; sections={'name': '.text', 'offset': 1536, 'size': 4172800, 'virtual_address': 4096, 'entropy': 6.188389033546932}, {'name': '.rdata', 'offset': 4174336, 'size': 4205056, 'virtual_address': 4177920, 'entropy': 5.685035404026879}, {'name': '.data', 'offset': 8379392, 'size': 396288, 'virtual_address': 8384512, 'entropy': 5.901060245078486}
  - Recommendation: Inspect high-entropy regions for compression, encryption, or packed payloads.
- **[info] YARA scanning unavailable**
  - Source: `yara_scan`
  - Detail: yara-python is not installed or the scanner could not start.
  - Confidence: 0.95
  - Evidence: rules_path=D:\Project\PE-reverse-skill\rules\yara; error=optional dependency yara-python unavailable: No module named 'yara'
  - Recommendation: Install yara-python to enable rule-based scanning with the bundled ruleset.

## Recommendations

- Validate whether the sample is packed, then focus manual reversing on the unpacked entry point and import resolution path.
- Inspect unpacking behavior and confirm whether imports or control flow are reconstructed at runtime.
- Inspect high-entropy regions for compression, encryption, or packed payloads.
- Install yara-python to enable rule-based scanning with the bundled ruleset.
- Prioritize containment and deeper manual validation of high-severity indicators.
- Inspect the entry point, suspicious sections, and overlay to confirm packer or obfuscation behavior.
- Install yara-python to enable rule-based scanning, or provide a compatible environment for YARA.
- Preserve generated artifacts and correlate findings against trusted threat-intelligence sources.

## Artifacts

- engine/fingerprint.json
- engine/metadata.json
- engine/assets.json
- engine/symbols.json
- engine/native_mapping.json
- engine/sdk_skeleton.json
- engine/semantic_ir_fragment.json
- android/manifest.json
- android/resources.json
- android/dex_summary.json
- android/native_libs.json
- android/framework.json
- android/java_decompilation.json
- android/semantic_ir_fragment.json
- protocol/flows.json
- protocol/field_stats.json
- protocol/inference.json
- analysis_graph.json
- semantic_ir.json
- evidence-manifest.json
