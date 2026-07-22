param(
    [string]$Output = "dist/reverse-jailbreak",
    [switch]$Clean,
    [switch]$NoBuildIsolation,
    [long]$SourceDateEpoch = 0
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

$ResolvedSourceDateEpoch = $SourceDateEpoch
if ($ResolvedSourceDateEpoch -le 0 -and -not [string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH)) {
    if (-not [long]::TryParse($env:SOURCE_DATE_EPOCH, [ref]$ResolvedSourceDateEpoch)) {
        throw "SOURCE_DATE_EPOCH must be an integer Unix timestamp"
    }
}
if ($ResolvedSourceDateEpoch -le 0) {
    $GitCommand = Get-Command git -ErrorAction SilentlyContinue
    if ($null -ne $GitCommand) {
        $GitEpochOutput = & git log -1 --format=%ct 2>$null
        if ($LASTEXITCODE -eq 0) {
            $GitEpoch = ([string]$GitEpochOutput).Trim()
            [void][long]::TryParse($GitEpoch, [ref]$ResolvedSourceDateEpoch)
        }
    }
}
if ($ResolvedSourceDateEpoch -le 0) {
    # ZIP-based wheels cannot represent timestamps before 1980-01-01.
    $ResolvedSourceDateEpoch = 315532800
}
if ($ResolvedSourceDateEpoch -lt 315532800) {
    throw "SourceDateEpoch must be at or after 1980-01-01"
}
$env:SOURCE_DATE_EPOCH = [string]$ResolvedSourceDateEpoch

$WheelArguments = @("-m", "pip", "wheel", ".", "--no-deps", "--wheel-dir", $Output)
if ($NoBuildIsolation) {
    # Offline/air-gapped builders use the already-installed build backend.
    $WheelArguments += "--no-build-isolation"
}
Invoke-Python @WheelArguments
Copy-Item schemas/jailbreak-campaign.schema.json $Output -Force
Copy-Item config/jailbreak-campaign.example.json $Output -Force
Copy-Item docs/reverse_jailbreak_release.md $Output -Force
Copy-Item CHANGELOG.md $Output -Force
$Version = (& python -c "from reverse_analyzer._version import __version__; print(__version__)").Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($Version)) {
    throw "could not resolve package version from reverse_analyzer._version"
}
$ReleaseNotes = Join-Path "docs/releases" ($Version + ".md")
if (-not (Test-Path -LiteralPath $ReleaseNotes -PathType Leaf)) {
    throw "missing release notes for package version ${Version}: $ReleaseNotes"
}
Copy-Item $ReleaseNotes (Join-Path $Output "RELEASE_NOTES.md") -Force
Copy-Item scripts/smoke_reverse_jailbreak_release.py (Join-Path $Output "smoke_release.py") -Force
Invoke-Python -m reverse_analyzer.llm_jailbreak.release build $Output
Invoke-Python -m reverse_analyzer.llm_jailbreak.release verify $Output
Write-Host "Portable package written to $Output"
