param(
    [string]$Manifest = "$PSScriptRoot\..\config\github-tools.lock.json",
    [string]$Destination = "$PSScriptRoot\..\.reverse_analyzer\external-tools",
    [string[]]$Tool = @(),
    [switch]$ListOnly
)

$ErrorActionPreference = 'Stop'
$manifestPath = (Resolve-Path -LiteralPath $Manifest).Path
$manifestData = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

if ($manifestData.schema_version -ne 1) { throw 'Unsupported GitHub tool manifest schema_version.' }
if ($manifestData.policy -ne 'official-source-only') { throw 'GitHub tool manifest must use official-source-only policy.' }
if ($manifestData.installation_policy -ne 'manual-reviewed-only') { throw 'GitHub tool manifest must use manual-reviewed-only installation policy.' }

$knownIds = @{}
foreach ($entry in @($manifestData.tools)) {
    if ([string]::IsNullOrWhiteSpace([string]$entry.id)) { throw 'Every manifest tool must have a non-empty id.' }
    if ($knownIds.ContainsKey([string]$entry.id)) { throw "Duplicate manifest tool id: $($entry.id)" }
    $knownIds[[string]$entry.id] = $true

    foreach ($urlValue in @([string]$entry.source, [string]$entry.download)) {
        $uri = $null
        if (-not [Uri]::TryCreate($urlValue, [UriKind]::Absolute, [ref]$uri) -or
            $uri.Scheme -ne 'https' -or $uri.Host -ne 'github.com') {
            throw "Tool '$($entry.id)' must reference an official HTTPS github.com URL."
        }
    }
    if ([string]::IsNullOrWhiteSpace([string]$entry.classification) -or
        [string]::IsNullOrWhiteSpace([string]$entry.distribution)) {
        throw "Tool '$($entry.id)' must declare classification and distribution."
    }
    foreach ($providerModule in @($entry.provider_modules)) {
        $relativeModule = [string]$providerModule
        if ([IO.Path]::IsPathRooted($relativeModule) -or [string]::IsNullOrWhiteSpace($relativeModule)) {
            throw "Tool '$($entry.id)' has an invalid provider module path."
        }
        $providerPath = [IO.Path]::GetFullPath((Join-Path $repositoryRoot $relativeModule))
        $rootPrefix = $repositoryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $providerPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetExtension($providerPath) -ne '.py' -or
            -not (Test-Path -LiteralPath $providerPath -PathType Leaf)) {
            throw "Tool '$($entry.id)' provider module must be an existing Python file inside the repository: $relativeModule"
        }
    }
}

if ($ListOnly) {
    $manifestData.tools | Select-Object id, classification, distribution, source, download, version, platforms, environment | Format-List
    exit 0
}

$unknownIds = @($Tool | Where-Object { -not $knownIds.ContainsKey([string]$_) })
if ($unknownIds.Count -gt 0) { throw "Unknown tool ids in the GitHub lock manifest: $($unknownIds -join ', ')" }

$selected = if ($Tool.Count -eq 0) { @($manifestData.tools) } else {
    @($manifestData.tools | Where-Object { $Tool -contains $_.id })
}
if ($selected.Count -eq 0) { throw 'No matching tool ids in the GitHub lock manifest.' }

$destinationPath = [IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Force -Path $destinationPath | Out-Null
$records = @()
foreach ($entry in $selected) {
    $record = [ordered]@{
        id = $entry.id
        source = $entry.source
        download = $entry.download
        version = $entry.version
        classification = $entry.classification
        distribution = $entry.distribution
        destination = $destinationPath
        status = 'manual-download-required'
        reason = 'The manifest intentionally does not download assets, guess release files, or execute third-party installers.'
        environment = @($entry.environment)
        recorded_at = [DateTime]::UtcNow.ToString('o')
    }
    $records += [pscustomobject]$record
    Write-Host ("{0}: {1}" -f $entry.id, $entry.download)
}

$auditPath = Join-Path $destinationPath 'github-tools-install-audit.json'
$audit = [ordered]@{
    schema_version = 1
    policy = 'official-source-only'
    generated_at = [DateTime]::UtcNow.ToString('o')
    records = $records
    next_step = 'Download from the listed official source, set the listed environment variable, then run python -m reverse_analyzer environment validate --json.'
}
$audit | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $auditPath -Encoding UTF8
Write-Host "Wrote audit: $auditPath"
