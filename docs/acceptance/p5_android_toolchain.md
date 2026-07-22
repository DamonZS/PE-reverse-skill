# P5 Android Toolchain Acceptance

P5 has four independent registered acceptance fixtures. Tool discovery or a
standalone smoke does not change capability status. Promotion requires the
fixture command to retain a hash-backed record that passes `environment accept
verify`.

## Reproducible CI entry point

The repository includes a manual workflow at
`.github/workflows/android-p5-live.yml`. It targets a self-hosted runner with
labels `self-hosted`, `linux`, and `android-p5`; the runner must have `adb`,
Python, and the selected external toolchain installed. The workflow performs
the same registered `environment accept run` and independent `verify` steps as
the local commands above, then uploads the complete acceptance workspace. It
does not run on push or schedule and it never promotes a capability row.

Configure the `android-p5-live` environment with these non-secret variables:
`ANDROID_P5_APK_PATH`, `ANDROID_P5_KEYSTORE_PATH`, `ANDROID_P5_KEY_ALIAS`,
`ANDROID_P5_PACKAGE`, and (for native patch) `ANDROID_P5_NATIVE_PATCH_SPEC`.
Store `ANDROID_P5_KS_PASS` and `ANDROID_P5_KEY_PASS` as environment secrets.
Paths refer to files already present on the self-hosted runner; no fixture APK,
keystore, patch spec, or device identity is checked into the repository.

## Jadx

Configure a real APK fixture and either put `jadx` on `PATH` or set
`JADX_PATH`. Then run:

```powershell
$env:ANDROID_JADX_LIVE_APK = 'D:\fixtures\fixture.apk'
$env:JADX_PATH = 'D:\tools\jadx\bin\jadx.bat'
python -m reverse_analyzer environment accept run `
  --fixture p5-android-jadx-live `
  --workspace D:\acceptance\p5-jadx `
  --execute `
  --timeout 900
```

The fixture requires generated Java or Kotlin source, an unchanged input APK
hash, target identity, toolchain metadata, one executed test, zero skips, and a
positive live-operation count. The retained record includes the Jadx summary
and generated source hashes. The production path first runs a bounded offline
`jadx --version` probe; the retained toolchain artifact includes its normalized
version and return code. A failed probe stops before the output directory or
decompilation command is created.

Independent verification also rechecks the decompilation JSON: the result must
be `passed`, the dependency and version probe must be `available`/`passed`, the
source-file count must be positive, the input APK must remain unchanged, and
the retained output must contain a `.java`, `.kt`, or `.kts` source file.

## APK Rebuild And Signing

Configure a real APK, keystore, alias and passwords. Put `apktool` and
`apksigner` on `PATH`, or set `APKTOOL_PATH` and `APKSIGNER_PATH`:

```powershell
$env:ANDROID_REBUILD_LIVE_APK = 'D:\fixtures\fixture.apk'
$env:ANDROID_REBUILD_LIVE_KEYSTORE = 'D:\fixtures\fixture.keystore'
$env:ANDROID_REBUILD_LIVE_KEY_ALIAS = 'fixture'
$env:ANDROID_REBUILD_LIVE_KS_PASS = '<from-secret-store>'
$env:ANDROID_REBUILD_LIVE_KEY_PASS = '<from-secret-store>'
$env:APKTOOL_PATH = 'D:\tools\apktool.bat'
$env:APKSIGNER_PATH = 'D:\Android\build-tools\apksigner.bat'
python -m reverse_analyzer environment accept run `
  --fixture p5-android-rebuild-sign-live `
  --workspace D:\acceptance\p5-rebuild `
  --execute `
  --timeout 900
```

The fixture executes `apktool`, signs and verifies with `apksigner`, retains a
copy of the verified APK with its SHA-256, confirms the source APK is unchanged,
and removes the operational output through provider rollback. Password values
must not appear in the retained JSON artifacts.

The provider redacts password-bearing argv values and matching values echoed by
tool stdout, stderr, or runner exceptions before command records and failure
details enter audit artifacts. This repository-level regression guarantee does
not replace the real apktool/apksigner promotion requirement.

Provider validation resolves both executables and runs bounded, read-only
version probes (`apktool --version` and `apksigner version`) before any rebuild
output is written. A path that merely exists but cannot start is reported as an
unavailable dependency together with the redacted probe command, return code,
and first diagnostic line.

Verify either resulting record independently:

```powershell
python -m reverse_analyzer environment accept verify `
  --record <workspace>\acceptance\records\<fixture>--<session>.json
```

Independent verification re-evaluates the registered fixture contract against
the retained record. It checks the structured command and expected artifact
patterns, reloads the target-identity artifact, scans retained JSON for
synthetic provenance, and rechecks the rollback and cleanup proof contents in
addition to recomputing artifact sizes and SHA-256 values. Editing a record's
hash list cannot turn an unverified restore or cleanup into live evidence.

Until a real record is retained and independently verified, both capability
rows remain `dependency-gated`.

## Frida Android Instrumentation

Use a dedicated test package and device. The fixture accepts `usb`, `local`,
`remote`, or an explicit Frida device identifier and supports bounded `spawn`
or `attach` mode:

```powershell
$env:ANDROID_FRIDA_LIVE_PACKAGE = 'com.example.fixture'
$env:ANDROID_FRIDA_LIVE_DEVICE = 'usb'
$env:ANDROID_FRIDA_LIVE_MODE = 'spawn'
python -m reverse_analyzer environment accept run `
  --fixture p5-android-frida-live `
  --workspace D:\acceptance\p5-frida `
  --execute `
  --timeout 900
```

Promotion requires real device/package identity, hash-backed audit/events/
rollback artifacts, and proof that spawn resume (when applicable), script
unload, and session detach all completed. The retained target identity uses the
device ID/name/type observed by Frida, not only the configured selector. The
default test path remains skipped until the fixture is explicitly enabled by the
acceptance runner.

## Native APK Patch And Device Rollback

Provide a real APK containing a native library, a JSON patch specification, a
test signing key, package name, and ADB-accessible test device. The patch spec
contains only bounded provider fields such as `abi`, `library_path`,
`file_offset` or `virtual_address`, `expected`, `replacement`, and
`instruction_mode`.

```powershell
$env:ANDROID_NATIVE_PATCH_LIVE_APK = 'D:\fixtures\fixture.apk'
$env:ANDROID_NATIVE_PATCH_LIVE_SPEC = 'D:\fixtures\native-patch.json'
$env:ANDROID_NATIVE_PATCH_LIVE_PACKAGE = 'com.example.fixture'
$env:ANDROID_NATIVE_PATCH_LIVE_KEYSTORE = 'D:\fixtures\fixture.keystore'
$env:ANDROID_NATIVE_PATCH_LIVE_KEY_ALIAS = 'fixture'
$env:ANDROID_NATIVE_PATCH_LIVE_KS_PASS = '<from-secret-store>'
$env:APKSIGNER_PATH = 'D:\Android\build-tools\apksigner.bat'
$env:ADB_PATH = 'D:\Android\platform-tools\adb.exe'
python -m reverse_analyzer environment accept run `
  --fixture p5-android-native-patch-live `
  --workspace D:\acceptance\p5-native-patch `
  --execute `
  --timeout 1200
```

The fixture verifies the patch and signature, installs and launches the patched
copy, uninstalls it, executes provider rollback, verifies the restored APK hash,
installs and launches the restored copy, and performs final device cleanup. It
retains the signed patched APK, provider evidence, deployment transcript,
rollback proof, target identity, and structured execution proof. Passwords are
read from environment variables and scanned out of retained JSON.

Promotion additionally requires the deployment transcript to mark installation
and launch as verified, and the execution proof to mark signature,
installation, launch, and rollback verification as true. The verifier
recomputes these fields instead of trusting the record's boolean summary.

Before the first install, the fixture records the ADB-reported serial and fails
closed unless the device is online and the fixture package is absent. This
prevents an existing installation from being overwritten and then removed by
the acceptance cleanup path. Cleanup is armed only after the first mutation is
attempted.

Verify either new record with the same `environment accept verify` command.
Until a real record is retained and independently verified, Frida and native
patch remain `dependency-gated`.
