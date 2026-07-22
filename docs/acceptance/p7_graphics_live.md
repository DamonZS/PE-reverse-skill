# P7 Graphics Live Acceptance

P7 has separate registered acceptance fixtures for passive PresentMon capture,
a production native Present bridge, D3D11 ImGui host lifecycle, and the combined
Present-to-matrix-to-projection-to-overlay path. A passing regression test does
not promote these fixtures. Promotion requires a retained record produced by
`environment accept run` and independently verified by `environment accept
verify`.

## Combined fixture

The `p7-graphics-combined-live` fixture requires an interactive Windows desktop,
a controlled D3D11 host with a stable PID/HWND, and a production local JSON
bridge. Configure:

```powershell
$env:REVERSE_ANALYZER_GRAPHICS_BRIDGE = '<graphics-bridge.exe>'
$env:REVERSE_ANALYZER_GRAPHICS_FIXTURE_PID = '<pid>'
$env:REVERSE_ANALYZER_GRAPHICS_FIXTURE_HWND = '<hwnd-or-0x-hwnd>'
python -m reverse_analyzer environment accept run `
  --fixture p7-graphics-combined-live `
  --workspace <acceptance-workspace> `
  --execute --timeout 300
```

The bridge probe must advertise `observe_present`, `acquire_matrix`, and `stop`
for `d3d11`. `acquire_matrix` must return the requested PID and HWND, a frame ID,
`source: native_host_bridge`, a 16-value matrix, explicit matrix/clip/handedness
metadata, viewport data, coordinate-system provenance, and one to 256 world
points. The fixture rejects test-double provenance and requires at least one
visible projected point.

The retained record binds and hashes target identity, Present observation,
matrix capture, projection output, production GDI overlay audit, graphics stop,
overlay resource cleanup, and structured non-skipped execution proof. Independent
verification also recomputes the cross-artifact contract: PID/HWND must agree,
Present and matrix frame IDs must match, projection/overlay provenance must bind
to that frame, and cleanup/execution proofs must be successful. Recomputing an
artifact hash after changing one of these relationships does not make the record
valid.

Verify the resulting immutable record:

```powershell
python -m reverse_analyzer environment accept verify --record <record.json>
```

## Separate Present and ImGui fixtures

`p4-native-graphics-bridge` gates on both the controlled PID and configured
graphics bridge and invokes only its dedicated acceptance test. The
`p4-imgui-d3d11-live` fixture gates on the official Dear ImGui checkout, target
PID, production ImGui bridge, and retained live Present-resolution evidence. It
also invokes only its dedicated production-build/host-lifecycle test.

The retained ImGui contract includes the built renderer DLL rather than only
its manifest. Independent verification recomputes the DLL size and SHA-256 and
binds the process target, D3D11 host plan, ordered load/initialize/hook/frame/
shutdown/unload lifecycle, native observation proofs, bridge executable digest,
hook restoration, cleanup, and execution proof to one session. Editing an
artifact and updating its recorded hash does not satisfy these cross-artifact
bindings.

No retained combined graphics or ImGui record is checked in. Until a real run
is retained and reviewed, Graphics Present and ImGui remain dependency-gated,
and the combined projection/overlay capability remains partial.
