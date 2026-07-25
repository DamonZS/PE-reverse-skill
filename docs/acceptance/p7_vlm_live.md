# P7 OpenAI-compatible VLM acceptance

The bundled `reverse_analyzer.gui.openai_vlm:OpenAICompatibleVLM` adapter sends
one bounded GUI image to an OpenAI-compatible `chat/completions` endpoint. The
registered `p7-vlm-openai-live` fixture remains opt-in and does not persist its
API key, Authorization header, endpoint URL, or source image path.

Configure the live inputs only in the process environment:

```powershell
$env:REVERSE_ANALYZER_RUN_VLM_LIVE = '1'
$env:REVERSE_ANALYZER_VLM_BASE_URL = 'https://HOST/v1'
$env:REVERSE_ANALYZER_VLM_MODEL = 'MODEL'
$env:REVERSE_ANALYZER_VLM_API_KEY = 'TOKEN'
$env:REVERSE_ANALYZER_VLM_IMAGE = 'D:\fixtures\gui-screen.png'
$env:REVERSE_ANALYZER_VLM_CANARY = 'VLM-CANARY-42'

python -m reverse_analyzer environment accept run `
  --fixture p7-vlm-openai-live `
  --workspace .\p7-vlm-acceptance `
  --execute `
  --timeout 120
```

The controlled image must visibly contain the unique canary. Promotion requires
a successful non-skipped HTTP operation, a normalized text or widget item that
contains that canary, image/endpoint/canary identity hashes, sanitized
invocation/output/transport artifacts, and an independently verified acceptance
record. The target identity stores the canary SHA-256 rather than the configured
canary value; normalized model output remains part of the retained evidence.
Loopback HTTP tests prove the production transport path but are not live model
evidence. Graphics Present, ImGui host integration, matrix acquisition, and
combined overlay behavior remain separate P7 gates.

Independent record verification recomputes the VLM semantic contract. It
requires valid content-addressed endpoint, image, and canary identities; binds
the transport `input_sha256` to the retained image digest; requires an
`openai-compatible-http` transport audit with environment-backed credentials;
and checks output provenance, visual evidence, canary matching, and a
non-skipped execution proof. Recomputing an artifact hash after changing one
of these relationships does not make the record valid.

The repository also provides a manual `P7 live acceptance` workflow. Configure
the `p7-vlm-live` environment variables `P7_VLM_BASE_URL`, `P7_VLM_MODEL`,
`P7_VLM_IMAGE`, and `P7_VLM_CANARY`, store the key as `P7_VLM_API_KEY`, and
dispatch `.github/workflows/p7-live.yml` with fixture `p7-vlm-openai-live`.
The `p7-vlm` self-hosted Linux runner must have the configured image path and
network access to the endpoint. The workflow uploads the run directory after
independent record verification. Each dispatch attempt writes to a distinct
`<run-id>-<run-attempt>` workspace, verifies only the single
`p7-vlm-openai-live--*.json` record from that workspace, and uploads only that
attempt's evidence directory. It does not modify the capability matrix.
