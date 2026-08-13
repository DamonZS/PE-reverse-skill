#Requires -Version 5.1
# reverse-skill routing + ops contract gates for the current Python router layout.
param([string] $ScratchDir = '')
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$skillsRoot = Split-Path -Parent $scriptDir
$packageRoot = Split-Path -Parent $skillsRoot
$masterRoute = Join-Path $scriptDir 'master-route.ps1'

$tmpBase = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
if (-not $ScratchDir) {
    $ScratchDir = Join-Path $tmpBase ("rs-verify-{0}" -f (Get-Date -Format 'yyyyMMddHHmmss'))
}
New-Item -ItemType Directory -Force -Path $ScratchDir | Out-Null
$fail = New-Object System.Collections.Generic.List[string]
function Ok($m) { Write-Host "[OK] $m" -ForegroundColor Green }
function Bad($m) { Write-Host "[FAIL] $m" -ForegroundColor Red; [void]$fail.Add($m) }

$routingJson = Join-Path $skillsRoot 'config/routing.json'
if (Test-Path -LiteralPath $routingJson) {
    $rj = Get-Content -LiteralPath $routingJson -Raw -Encoding UTF8 | ConvertFrom-Json
    $routes = @($rj.routes)
    if ($routes.Count -ge 25) { Ok "routing.json routes=$($routes.Count)" } else { Bad 'routing.json route count suspicious (<25)' }
    $badRoute = @($routes | Where-Object { -not $_.skill_id -or -not $_.title -or -not $_.keywords })
    if ($badRoute.Count -eq 0) { Ok 'routing.json: all routes have skill_id/title/keywords' } else { Bad "routing.json routes missing fields: $($badRoute.Count)" }
    $missingRouteSkills = @($routes | Where-Object {
        $skillDir = Join-Path $skillsRoot ($_.skill_id -replace '/', [IO.Path]::DirectorySeparatorChar)
        $skillFile = Join-Path $skillDir 'SKILL.md'
        -not (Test-Path -LiteralPath $skillFile)
    })
    if ($missingRouteSkills.Count -eq 0) { Ok 'routing.json: all route skills exist' } else { Bad "routing.json missing skill files: $(($missingRouteSkills | ForEach-Object { $_.skill_id }) -join ',')" }
} else {
    Bad 'skills/config/routing.json missing (single source of truth)'
}

$benchJson = Join-Path $skillsRoot 'tests/routing-benchmark.json'
if (Test-Path -LiteralPath $benchJson) {
    $bj = Get-Content -LiteralPath $benchJson -Raw -Encoding UTF8 | ConvertFrom-Json
    $bjCases = @($bj.cases)
    if ($bjCases.Count -ge 100) { Ok "benchmark cases=$($bjCases.Count)" } else { Bad "benchmark cases < 100 ($($bjCases.Count))" }
    $badExpect = @($bjCases | Where-Object { $_.expect -notmatch '^R\d+$' })
    if ($badExpect.Count -eq 0) { Ok 'benchmark expect ids well-formed' } else { Bad "benchmark bad expect: $($badExpect.Count)" }
} else {
    Bad 'skills/tests/routing-benchmark.json missing'
}

if (Test-Path -LiteralPath (Join-Path $skillsRoot 'INDEX.md')) { Ok 'INDEX.md present (generated)' } else { Bad 'INDEX.md missing' }

$opsFiles = @(
    'ops/IDENTITY.md',
    'ops/scope-contract.md',
    'ops/evidence-finding-path.md',
    'ops/role-map.md',
    'ops/timeline-workitem.md',
    'ops/sandbox-profile.md',
    'ops/skill-supply-chain.md',
    'ops/README.md',
    'references/community-security-skills.md',
    'references/domain-coverage-map.md',
    'attack-chain/references/lifecycle-checklist.md',
    'reverse-engineering/references/re-agent-workflow.md',
    'pentest-tools/references/recon-pipeline.md',
    'MASTER-ROUTING.md',
    'scripts/master-route.py',
    'scripts/case-init.py',
    'scripts/verify-skill-suite.py',
    'scripts/verify-routing-coherence.ps1',
    'scripts/case-guard.ps1',
    'scripts/append-evidence.ps1',
    'scripts/test-routing.ps1',
    'scripts/smoke.ps1',
    'scripts/lib/WorkRoot.ps1',
    'case-review/SKILL.md',
    'case-review/scripts/review_case.py',
    'docs-generator/references/security-report-templates.md',
    'field-journal/_template.md'
)
foreach ($rel in $opsFiles) {
    $p = Join-Path $skillsRoot $rel
    if (Test-Path -LiteralPath $p) { Ok "artifact $rel" } else { Bad "missing $rel" }
}

foreach ($hub in @('MASTER-ROUTING.md', 'SKILL.md', 'ops/README.md')) {
    $hp = Join-Path $skillsRoot $hub
    if (-not (Test-Path -LiteralPath $hp)) {
        Bad "missing hub $hub"
        continue
    }
    $t = Get-Content -LiteralPath $hp -Raw -Encoding UTF8
    if ($t -match 'scope-contract|case-init') { Ok "hub link scope in $hub" } else { Bad "hub $hub missing scope/case-init link" }
    if ($t -match 'IDENTITY\.md') { Ok "hub identity $hub" } else { Bad "hub $hub missing IDENTITY" }
}

$cases = @(
    @{ N = 'apk'; H = 'decompile APK with jadx apktool smali'; Id = 'R1' },
    @{ N = 'ios'; H = 'ios reverse objection mobsf'; Id = 'R2' },
    @{ N = 'js'; H = 'js reverse webpack encrypted param'; Id = 'R3' },
    @{ N = 'dsl'; H = 'dsl vm reverse fireye'; Id = 'R4' },
    @{ N = 'dotnet'; H = '.net reverse dnspy de4dot'; Id = 'R5' },
    @{ N = 'ida'; H = 'IDA decompile PE'; Id = 'R6' },
    @{ N = 'radare2'; H = 'radare2 analyze binary'; Id = 'R7' },
    @{ N = 'malware'; H = 'malware analysis yara'; Id = 'R9' },
    @{ N = 'attack'; H = 'full pentest attack chain'; Id = 'R10' },
    @{ N = 'pentest'; H = 'nmap nuclei sqlmap'; Id = 'R11' },
    @{ N = 'api'; H = 'api security graphql bola'; Id = 'R12' },
    @{ N = 'case'; H = 'case review evidence chain traceability'; Id = 'R40' }
)
foreach ($c in $cases) {
    $out = Join-Path $ScratchDir ("route-{0}" -f $c.N)
    $stdout = & powershell -NoProfile -ExecutionPolicy Bypass -File $masterRoute -Hint $c.H -OutDir $out 2>&1 | Out-String
    $stdout | Set-Content -LiteralPath (Join-Path $ScratchDir ("route-{0}.txt" -f $c.N)) -Encoding UTF8
    $scope = Join-Path $out 'route-scope.md'
    if (-not (Test-Path $scope)) { Bad "no scope $($c.N)"; continue }
    $text = Get-Content $scope -Raw -Encoding UTF8
    if ($text -notmatch ("primary: {0}" -f [regex]::Escape($c.Id))) { Bad "$($c.N) id want $($c.Id)" } else { Ok "$($c.N) -> $($c.Id)" }
}

$summary = @(
    "FAIL_COUNT=$($fail.Count)",
    "ScratchDir=$ScratchDir"
)
$summary -join [Environment]::NewLine | Set-Content -LiteralPath (Join-Path $ScratchDir 'SUMMARY.txt') -Encoding UTF8
if ($fail.Count -gt 0) {
    Write-Host 'OVERALL: FAIL' -ForegroundColor Red
    exit 1
}
Write-Host 'OVERALL: ALL PASS' -ForegroundColor Green
exit 0
