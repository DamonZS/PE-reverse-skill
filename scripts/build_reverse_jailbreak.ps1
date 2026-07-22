param(
    [string]$Output = "dist/reverse-jailbreak",
    [switch]$Clean
)
$ErrorActionPreference = "Stop"

function Invoke-Python {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "python $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

if ((Test-Path $Output) -and $Clean) {
    Remove-Item -LiteralPath $Output -Recurse -Force
}
New-Item -ItemType Directory -Path $Output -Force | Out-Null
Invoke-Python -m pip wheel . --no-deps --wheel-dir $Output
Copy-Item schemas/jailbreak-campaign.schema.json $Output -Force
Copy-Item config/jailbreak-campaign.example.json $Output -Force
Copy-Item docs/reverse_jailbreak_release.md $Output -Force
Copy-Item CHANGELOG.md $Output -Force
Copy-Item docs/releases/0.1.0.md (Join-Path $Output "RELEASE_NOTES.md") -Force
Copy-Item scripts/smoke_reverse_jailbreak_release.py (Join-Path $Output "smoke_release.py") -Force
Invoke-Python -m reverse_analyzer.llm_jailbreak.release build $Output
Invoke-Python -m reverse_analyzer.llm_jailbreak.release verify $Output
Write-Host "Portable package written to $Output"
