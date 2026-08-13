#Requires -Version 5.1
# reverse-skill smoke entrypoint: verify + script parse + master-route sample matrix.
param(
    [string] $LogDir = ''
)
$ErrorActionPreference = 'Continue'

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$skillsRoot = Split-Path -Parent $scriptDir

if ([string]::IsNullOrWhiteSpace($LogDir)) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $tmpBase = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
    $LogDir = Join-Path $tmpBase ("rs-smoke-{0}" -f $stamp)
}
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

$fail = New-Object System.Collections.Generic.List[string]
function Ok([string] $m) { Write-Host ("[OK] {0}" -f $m) -ForegroundColor Green }
function Bad([string] $m) {
    Write-Host ("[FAIL] {0}" -f $m) -ForegroundColor Red
    [void]$fail.Add($m)
}

Write-Host ("=== reverse-skill smoke | LogDir={0} ===" -f $LogDir)

$verify = Join-Path $scriptDir 'verify-routing-coherence.ps1'
if (-not (Test-Path -LiteralPath $verify)) {
    Bad 'verify-routing-coherence.ps1 missing'
    $verifyExit = 1
} else {
    $vLog = Join-Path $LogDir '01-verify.txt'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $verify 2>&1 | Tee-Object -FilePath $vLog | Out-Null
    $verifyExit = $LASTEXITCODE
    if ($verifyExit -eq 0) { Ok 'verify-routing-coherence exit 0' } else { Bad ("verify-routing-coherence exit {0}" -f $verifyExit) }
}

$scripts = @(
    'verify-routing-coherence.ps1',
    'master-route.ps1',
    'case-init.ps1',
    'lib\WorkRoot.ps1',
    'bootstrap-reverse.ps1',
    'refresh-tool-index.ps1',
    'smoke.ps1',
    'append-evidence.ps1',
    'case-guard.ps1',
    'test-routing.ps1'
)
$parseOk = 0
$parseFail = 0
$parseLog = New-Object System.Collections.Generic.List[string]
foreach ($name in $scripts) {
    $p = Join-Path $scriptDir $name
    if (-not (Test-Path -LiteralPath $p)) {
        Bad ("script missing: {0}" -f $name)
        $parseFail++
        [void]$parseLog.Add("MISSING $name")
        continue
    }
    $errs = $null
    $tokens = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tokens, [ref]$errs)
    if ($errs -and $errs.Count -gt 0) {
        Bad ("parse fail {0}: {1}" -f $name, $errs[0].Message)
        $parseFail++
        [void]$parseLog.Add("FAIL $name $($errs[0].Message)")
    } else {
        Ok ("parse {0}" -f $name)
        $parseOk++
        [void]$parseLog.Add("OK $name")
    }
}
$parseLog -join [Environment]::NewLine | Set-Content (Join-Path $LogDir '02-parse.txt') -Encoding UTF8

$mr = Join-Path $scriptDir 'master-route.ps1'
$cases = @(
    @{ Name = 'apk'; Hint = 'decompile APK with jadx apktool smali'; Expect = 'R1' },
    @{ Name = 'ios'; Hint = 'ios reverse objection mobsf'; Expect = 'R2' },
    @{ Name = 'js'; Hint = 'js reverse webpack encrypted param'; Expect = 'R3' },
    @{ Name = 'dsl'; Hint = 'dsl vm reverse fireye'; Expect = 'R4' },
    @{ Name = 'dotnet'; Hint = '.net reverse dnspy de4dot'; Expect = 'R5' },
    @{ Name = 'ida'; Hint = 'IDA decompile PE'; Expect = 'R6' },
    @{ Name = 'radare2'; Hint = 'radare2 analyze binary'; Expect = 'R7' },
    @{ Name = 'malware'; Hint = 'malware analysis yara'; Expect = 'R9' },
    @{ Name = 'attack'; Hint = 'full pentest attack chain'; Expect = 'R10' },
    @{ Name = 'pentest'; Hint = 'nmap nuclei sqlmap'; Expect = 'R11' },
    @{ Name = 'api'; Hint = 'api security graphql bola'; Expect = 'R12' },
    @{ Name = 'case'; Hint = 'case review evidence chain traceability'; Expect = 'R40' }
)
$routeOk = 0
$routeFail = 0
$routeSummary = New-Object System.Collections.Generic.List[string]
if (-not (Test-Path -LiteralPath $mr)) {
    Bad 'master-route.ps1 missing'
} else {
    foreach ($c in $cases) {
        $tmp = Join-Path $LogDir ("route-{0}" -f $c.Name)
        $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File $mr -Hint $c.Hint -OutDir $tmp 2>&1 | Out-String
        $raw | Set-Content -Path (Join-Path $LogDir ("route-{0}.txt" -f $c.Name)) -Encoding UTF8
        $scope = Join-Path $tmp 'route-scope.md'
        $got = ''
        if (Test-Path -LiteralPath $scope) {
            $scopeText = Get-Content -LiteralPath $scope -Raw -Encoding UTF8
            if ($scopeText -match 'primary:\s*(\S+)') { $got = $Matches[1] }
        }
        if ($got -eq $c.Expect) {
            Ok ("route {0} -> {1}" -f $c.Name, $c.Expect)
            $routeOk++
            [void]$routeSummary.Add("PASS $($c.Name)")
        } else {
            Bad ("route {0} expect {1} got {2}" -f $c.Name, $c.Expect, $(if ($got) { $got } else { 'NONE' }))
            $routeFail++
            [void]$routeSummary.Add("FAIL $($c.Name)")
        }
    }
}
$routeSummary -join [Environment]::NewLine | Set-Content (Join-Path $LogDir '03-route-summary.txt') -Encoding UTF8

$appendEvidence = Join-Path $scriptDir 'append-evidence.ps1'
$evidenceCase = Join-Path $LogDir 'evidence-immutability'
if (-not (Test-Path -LiteralPath $appendEvidence)) {
    Bad 'append-evidence.ps1 missing for immutability check'
} else {
    New-Item -ItemType Directory -Path $evidenceCase -Force | Out-Null
    & powershell -NoProfile -ExecutionPolicy Bypass -File $appendEvidence `
        -CaseRoot $evidenceCase `
        -Id 'E-IMMUTABLE' `
        -Title 'first write' `
        -ReproCommand 'echo first' 2>&1 | Out-Null
    $firstEvidenceExit = $LASTEXITCODE
    if ($firstEvidenceExit -ne 0) {
        Bad ("initial Evidence append exit {0}" -f $firstEvidenceExit)
    } else {
        $evidencePath = Join-Path $evidenceCase 'evidence\E-IMMUTABLE.md'
        $indexPath = Join-Path $evidenceCase 'evidence\INDEX.md'
        $beforeEvidence = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash
        $beforeIndex = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash

        & powershell -NoProfile -ExecutionPolicy Bypass -File $appendEvidence `
            -CaseRoot $evidenceCase `
            -Id 'E-IMMUTABLE' `
            -Title 'second write' `
            -ReproCommand 'echo second' 2>&1 | Out-Null
        $duplicateEvidenceExit = $LASTEXITCODE

        $afterEvidence = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash
        $afterIndex = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash
        if ($duplicateEvidenceExit -eq 0) {
            Bad 'duplicate Evidence ID was accepted'
        } elseif ($beforeEvidence -ne $afterEvidence) {
            Bad 'existing Evidence changed after duplicate append'
        } elseif ($beforeIndex -ne $afterIndex) {
            Bad 'Evidence index changed after duplicate append'
        } else {
            Ok 'duplicate Evidence ID rejected without mutation'
        }
    }
}

$summary = @(
    "VERIFY_EXIT=$verifyExit",
    "PARSE ok=$parseOk fail=$parseFail",
    "ROUTE ok=$routeOk fail=$routeFail / $($cases.Count)",
    "FAIL_COUNT=$($fail.Count)",
    "LogDir=$LogDir"
)
$summary -join [Environment]::NewLine | Set-Content (Join-Path $LogDir 'SUMMARY.txt') -Encoding UTF8
Write-Host '=== SMOKE SUMMARY ==='
$summary | ForEach-Object { Write-Host $_ }
if ($fail.Count -gt 0) {
    $fail | Set-Content (Join-Path $LogDir 'failures.txt') -Encoding UTF8
    Write-Host 'OVERALL: FAIL' -ForegroundColor Red
    exit 1
}
Write-Host 'OVERALL: ALL PASS' -ForegroundColor Green
exit 0
