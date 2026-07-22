# Reverse Jailbreak Portable Release

Build a wheel and copy the schema/configuration assets with:

```powershell
./scripts/build_reverse_jailbreak.ps1 -Clean
```

For an offline or air-gapped builder with `setuptools` already installed, add
`-NoBuildIsolation` so pip does not attempt to download build dependencies:

```powershell
./scripts/build_reverse_jailbreak.ps1 -Clean -NoBuildIsolation
```

Install the wheel, then use the standalone entry point:

```powershell
reverse-jailbreak init .\campaign-workspace
reverse-jailbreak profiles
reverse-jailbreak strategies
reverse-jailbreak validate config/jailbreak-campaign.example.json
reverse-jailbreak doctor --base-url https://HOST/v1 --model MODEL --api-key-env MODEL_API_KEY
reverse-jailbreak run campaign.json --out out
reverse-jailbreak resume campaign.json --out out
reverse-jailbreak report out --json
reverse-jailbreak promote out --secret-env MODEL_API_KEY
reverse-jailbreak release-verify dist/reverse-jailbreak
python dist/reverse-jailbreak/smoke_release.py dist/reverse-jailbreak
```

`init` materializes the packaged starter campaign and JSON Schema, so a wheel
installation can create a working configuration without a source checkout. It
stops before overwriting existing files unless `--force` is explicit and emits
per-file size and SHA-256 metadata with `--json`.

The API key is referenced by environment variable only. The campaign schema is
`schemas/jailbreak-campaign.schema.json`; no credential field is accepted by
the campaign loader. All five built-in instruction profiles are included as
wheel package data, so an installed release does not depend on a source checkout.
The build also writes `release-manifest.json` with the product version and exact
size and SHA-256 of the wheel, schema, starter configuration, changelog, release
notes, release guide, and smoke runner. `release-verify` rejects version drift,
multiple wheels, missing, modified, path-escaping, duplicate, and untracked
files, as well as obvious API credential or Authorization bearer values in
release contents. Before installation, the standalone smoke runner independently
checks every manifest path, size, and SHA-256 and rejects missing, extra, or
symlinked files. It then creates a temporary virtual environment, installs the
wheel with its declared dependencies, and exercises every installed command:
`init`, `doctor`, `profiles`, `strategies`, `validate`, `run`, `resume`, `report`,
`promote`, `benchmark`, and `release-verify`. Endpoint checks and campaign runs
use a temporary loopback-only OpenAI-compatible fixture and a disposable
environment-variable credential, so package smoke does not require an external
endpoint or retained secret. Use `-Clean` for repeated builds. The build script
sets `SOURCE_DATE_EPOCH` from `-SourceDateEpoch`, an existing environment value,
or the current Git commit timestamp (with a 1980 ZIP-compatible fallback), so
unchanged source produces a byte-identical wheel and release manifest.

The normal release CI builds, verifies, installs, and smokes the package without
calling an external model endpoint. It is triggered by changes anywhere in the
packaged `reverse_analyzer` tree as well as release dependencies and metadata.
The compatibility matrix covers the declared Python 3.10 floor on Windows, the
canonical Windows/Python 3.12 artifact build, and Python 3.13 on Ubuntu. Every
matrix entry builds and installs the wheel; only the canonical entry uploads a
release artifact. The retained live acceptance workflow is manual-only and uses
the protected `llm-jailbreak-live` GitHub environment.

## Reproducible algorithm benchmark

Run all five campaign algorithms with the same campaign seed and maximum-round
budget. Each algorithm is isolated in its own output directory, and every run
performs a completed-checkpoint resume check without issuing another request.

```powershell
reverse-jailbreak benchmark .\campaign.json `
  --out .\benchmark-out `
  --repetitions 3 `
  --max-rounds 8 `
  --model MODEL_A --model MODEL_B `
  --instruction-profile ctf-sandbox `
  --prompt-cost-per-1k 0.001 `
  --completion-cost-per-1k 0.002
```

Repeated `--algorithm` options select a subset; comma-separated values are also
accepted. `benchmark.json` records the normalized matrix, reproducibility
fingerprint, per-run metrics, and aggregate breakthrough rate, attempts, tokens,
estimated cost, latency, semantic-judge agreement, and completed-checkpoint
recovery rate.
`benchmark.md` contains the corresponding comparison table. Cost uses only the
explicit prices passed to the command. Judge agreement compares the campaign
scorer result with the semantic judge verdict and is `null` when no verdict was
emitted.
