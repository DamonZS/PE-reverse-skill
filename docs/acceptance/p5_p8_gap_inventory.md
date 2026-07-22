# P5-P8 Gap Inventory

This inventory records the remaining external acceptance gates and the release
artifacts added in this work. `dependency-gated` means the implementation and
offline tests exist, but a real toolchain/device/desktop target is still needed.

| Phase | Capability groups | Current state | Real acceptance gap |
|---|---|---|---|
| P5 | Android rebuild/signing, Java decompilation, dynamic instrumentation, native patch | dependency-gated | Jadx, rebuild/sign, Frida lifecycle, and native patch/sign/install/launch/rollback all have registered retained-promotion fixtures. Real promoted toolchain/device records are still required. |
| P6 | Protocol analysis and runtime replay | offline analysis and the bounded IPv4/IPv6 loopback TCP/UDP, HTTP/1.1, verified TLS, mutation, ordered session replay, and bounded CONNECT capture subset are done; general capture/replay remains partial | Arbitrary interfaces, unmanaged TLS sessions, generalized CONNECT replay, HTTP/2/3, unrestricted remote endpoints, and broad cross-transport replay |
| P7 | Graphics/ImGui, overlays, UIA/VLM, source reconstruction, target control | UIA bounded scope done; VLM production adapter and opt-in fixture implemented with controlled-image canary binding; graphics Present, ImGui and combined matrix/projection/GDI overlay have registered retained-acceptance entry points | Retained OpenAI-compatible VLM endpoint/image/canary evidence; execute the graphics fixtures against a production bridge and controlled graphics host; live control backends |
| P8 | Dashboard, KnowledgeBase, LLM campaign | done for bounded scope | Continued periodic live regression and product packaging; no endpoint acceptance blocker remains |

## Release additions

The standalone package now provides the `reverse-jailbreak` console entry point,
`doctor`, `profiles`, `strategies`, `validate`, `run`, `resume`, `report`,
`promote`, `benchmark`, and `release-verify`.
The JSON schema is `schemas/jailbreak-campaign.schema.json`, the starter
configuration is `config/jailbreak-campaign.example.json`, and
`scripts/build_reverse_jailbreak.ps1` builds a portable wheel plus these assets.

These artifacts do not claim to close the external P5-P7 gates; they make the
existing bounded implementations installable, inspectable, and repeatable.

P6 additionally has the opt-in `p6-protocol-runtime-loopback` registered
acceptance fixture. Its exact evidence contract and remaining boundary are in
`docs/acceptance/p6_protocol_runtime.md`.

P5 now has separate registered fixtures for real Jadx decompilation, APK
rebuild/sign/verify/rollback, Frida attach-or-spawn lifecycle cleanup, and native
APK patch/sign/device deployment/launch/rollback. Their environment contracts
and promotion commands are documented in
`docs/acceptance/p5_android_toolchain.md`.

P7 graphics acceptance is documented in `docs/acceptance/p7_graphics_live.md`.
The combined fixture binds an observed D3D11 Present event and bridge-acquired
view-projection matrix to the same PID/HWND and frame, then projects
bridge-supplied world points and renders them through the production external
GDI overlay. The entry point and hash-backed retention contract are checked in;
no retained run is claimed by this inventory.
