# Reverse Jailbreak Workspace Initialization

An installed `reverse-jailbreak` wheel carries the canonical campaign starter
and its JSON Schema. Materialize both files without a source checkout:

```powershell
reverse-jailbreak init .\campaign-workspace
reverse-jailbreak validate .\campaign-workspace\jailbreak-campaign.example.json
```

`init` writes `jailbreak-campaign.example.json` and
`jailbreak-campaign.schema.json`. It reports each file's size and SHA-256 with
`--json`. Existing files stop the operation before any template is written;
use `--force` only when restoring both files from the installed package:

```powershell
reverse-jailbreak init .\campaign-workspace --force --json
```

The packaged copies are byte-for-byte checked against `config/` and `schemas/`
by the release test suite, preventing the wheel and portable release assets
from drifting apart.
