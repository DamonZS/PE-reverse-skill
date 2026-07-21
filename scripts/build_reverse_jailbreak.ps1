param(
    [string]$Output = "dist/reverse-jailbreak",
    [switch]$Clean
)
$ErrorActionPreference = "Stop"
if ((Test-Path $Output) -and $Clean) {
    Remove-Item -LiteralPath $Output -Recurse -Force
}
New-Item -ItemType Directory -Path $Output -Force | Out-Null
python -m pip wheel . --no-deps --wheel-dir $Output
Copy-Item schemas/jailbreak-campaign.schema.json $Output -Force
Copy-Item config/jailbreak-campaign.example.json $Output -Force
Copy-Item docs/reverse_jailbreak_release.md $Output -Force
Copy-Item CHANGELOG.md $Output -Force
Copy-Item docs/releases/0.1.0.md (Join-Path $Output "RELEASE_NOTES.md") -Force
Copy-Item scripts/smoke_reverse_jailbreak_release.py (Join-Path $Output "smoke_release.py") -Force
python -m reverse_analyzer.llm_jailbreak.release build $Output
python -m reverse_analyzer.llm_jailbreak.release verify $Output
Write-Host "Portable package written to $Output"
