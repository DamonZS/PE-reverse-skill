# P8 LLM Periodic Live Acceptance

The retained live endpoint workflow is
`.github/workflows/reverse-jailbreak-live-e2e.yml`. It supports both a manual
dispatch and an opt-in monthly run at `03:17 UTC` on the first day of each
month.

## Repository Configuration

Periodic execution is disabled until the repository variable
`LLM_JAILBREAK_PERIODIC_ENABLED` is set to `1`. The protected
`llm-jailbreak-live` environment must provide:

- repository variable `LLM_JAILBREAK_E2E_BASE_URL`
- repository variable `LLM_JAILBREAK_E2E_MODEL`
- environment secret `MODEL_API_KEY`

Manual dispatch values override the two repository variables. API credentials
are always read from the environment secret and are never accepted as workflow
inputs.

## Acceptance Contract

Each enabled run executes the existing opt-in live E2E, which covers doctor,
plan, validate, HTTP execution, checkpoint, cross-session resume, report, and
promotion. The workflow then requires `promotion.json` and every promotion
check to report `passed`.

The complete `retained-evidence` directory is uploaded for 30 days even when a
step fails, so timeout, endpoint, schema, checkpoint, manifest, or redaction
regressions remain diagnosable. A scheduled success is regression evidence; it
does not silently replace the checked-in acceptance record or change the skill
parity matrix.

## Offline Contract Test

```powershell
python -m unittest tests.test_llm_jailbreak_live_workflow
```

This test verifies the opt-in gate, schedule, variable/secret wiring,
configuration preflight, promotion assertion, and failure-time artifact
retention without contacting an endpoint.
