#Requires -Version 5.1
# reverse-skill PRIMARY router wrapper for the current Python router.
param(
    [string] $Hint = '',
    [string] $OutDir = '',
    [string] $ProjectRoot = ''
)
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$skillsRoot = Split-Path -Parent $scriptDir
. (Join-Path (Join-Path $scriptDir 'lib') 'WorkRoot.ps1')
$projectRoot = Resolve-ReverseProjectRoot -RequestedRoot $ProjectRoot

function Resolve-PythonPath {
    $candidates = @(
        'C:\Users\Damon\.workbuddy\binaries\python\envs\default\Scripts\python.exe',
        'C:\Users\Damon\.workbuddy\binaries\python\versions\3.13.12\python.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cmd = Get-Command py -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw 'Python runtime not found for master-route.ps1'
}

$python = Resolve-PythonPath
$router = Join-Path $scriptDir 'master-route.py'
if (-not (Test-Path -LiteralPath $router -PathType Leaf)) {
    Write-Host ("ERROR: router script missing: {0}" -f $router) -ForegroundColor Red
    exit 2
}

$routeIdMap = @{
    'apk-reverse' = 'R1'
    'mobile-reverse' = 'R2'
    'js-reverse' = 'R3'
    'reverse-engineering/dsl-vm-reverse' = 'R4'
    'dotnet-analysis' = 'R5'
    'dotnet-reverse' = 'R5'
    'ida-reverse' = 'R6'
    'radare2' = 'R7'
    'firmware-pentest' = 'R8'
    'malware-analysis' = 'R9'
    'attack-chain' = 'R10'
    'pentest-tools' = 'R11'
    'api-security' = 'R12'
    'supply-chain-security' = 'R13'
    'llm-security' = 'R14'
    'binary-diff' = 'R15'
    'patch-diff-exploit' = 'R16'
    'pwn-chain' = 'R17'
    'edr-bypass-re' = 'R18'
    'browser-automation' = 'R19'
    'docs-generator' = 'R20'
    'protocol-reverse' = 'R21'
    'ghidra-reverse' = 'R22'
    'cloud-k8s' = 'R23'
    'windows-ad' = 'R24'
    'digital-forensics' = 'R25'
    'code-audit' = 'R26'
    'threat-hunting' = 'R27'
    'ot-ics' = 'R28'
    'wifi-wireless' = 'R29'
    'browser-extension-reverse' = 'R30'
    'macos-reverse' = 'R31'
    'thick-client' = 'R32'
    'go-rust-reverse' = 'R33'
    'hardware-security' = 'R34'
    'database-security' = 'R35'
    'email-security' = 'R36'
    'identity-federation' = 'R37'
    'radio-sdr' = 'R38'
    'diagram-generator' = 'R39'
    'case-review' = 'R40'
    'pe-triage' = 'R41'
    'interface-analysis' = 'R42'
    'package-analysis' = 'R43'
    'protection-review' = 'R44'
    'edr-defense-review' = 'R45'
    'pe-static-analysis' = 'R46'
    'pe-deep-analysis' = 'R47'
    'source-reconstruction' = 'R48'
    'reverse-engineering' = 'R0'
}

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $workRoot = Join-Path $projectRoot 'work'
    $OutDir = Join-Path $workRoot ("master-route-{0}" -f $stamp)
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$args = @($router, '--format', 'json')
if ([string]::IsNullOrWhiteSpace($Hint)) {
    $args += @('--intent', '')
} else {
    $args += @('--intent', $Hint)
}

$raw = & $python @args 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    Write-Host $raw -ForegroundColor Red
    exit 2
}

try {
    $result = $raw | ConvertFrom-Json
} catch {
    Write-Host ("ERROR: master-route.py did not return valid JSON: {0}" -f $_.Exception.Message) -ForegroundColor Red
    exit 2
}

$primarySkillId = [string]$result.skill_id
$primarySkillPath = [string]$result.skill_path
$primaryTitle = [string]$result.title
$primaryId = if ($routeIdMap.ContainsKey($primarySkillId)) { $routeIdMap[$primarySkillId] } else { 'R0' }
$secondary = @()
if ($null -ne $result.route -and $null -ne $result.route.secondary) {
    foreach ($item in @($result.route.secondary)) {
        if ($null -ne $item.skill_id) {
            $secondary += ("skills/{0}/SKILL.md" -f [string]$item.skill_id)
        }
    }
}
$secondaryText = if ($secondary.Count -gt 0) { $secondary -join ', ' } else { '(none)' }
$confidence = 'medium'
if ($result.route -and $result.route.secondary) {
    $secondaryCount = @($result.route.secondary).Count
    if ($secondaryCount -eq 0) { $confidence = 'high' }
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('# reverse-skill Master route (PRIMARY)')
[void]$sb.AppendLine(("- created: {0}" -f (Get-Date -Format 'o')))
[void]$sb.AppendLine('- package: reverse-skill')
[void]$sb.AppendLine(("- hint: {0}" -f $Hint))
[void]$sb.AppendLine(("- primary: {0}" -f $primaryId))
[void]$sb.AppendLine(("- primary_label: {0}" -f $primaryTitle))
[void]$sb.AppendLine(("- primary_skill: skills/{0}" -f $primarySkillPath))
[void]$sb.AppendLine(("- confidence: {0}" -f $confidence))
[void]$sb.AppendLine(("- project_root: {0}" -f $projectRoot))
[void]$sb.AppendLine(("- secondary: {0}" -f $secondaryText))
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## MUST open next')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('1. skills/MASTER-ROUTING.md')
[void]$sb.AppendLine(("2. skills/{0}" -f $primarySkillPath))
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Notes')
if ([string]::IsNullOrWhiteSpace($Hint)) {
    [void]$sb.AppendLine('- Empty hint; provide task text for stronger routing confidence.')
} else {
    [void]$sb.AppendLine('- Routed via scripts/master-route.py and legacy route ID mapping.')
}

$utf8 = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText((Join-Path $OutDir 'route-scope.md'), $sb.ToString(), $utf8)

Write-Host ("PRIMARY -> skills/{0}" -f $primarySkillPath) -ForegroundColor Green
Write-Host ("Label: {0} | confidence: {1}" -f $primaryTitle, $confidence)
Write-Host ("Wrote {0}\route-scope.md" -f $OutDir)
Write-Host 'ACTION: Open PRIMARY SKILL.md now and execute ACTION REQUIRED.' -ForegroundColor Yellow
exit 0
