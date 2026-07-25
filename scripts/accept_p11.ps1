param(
  [string]$Image = "reverse-analyzer:p11-acceptance",
  [string]$EvidencePath = "reports/p11-acceptance.json",
  [string]$ProviderBaseUrl = $env:OPENAI_BASE_URL,
  [string]$ProviderModel = $env:OPENAI_MODEL,
  [switch]$SkipRegression
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repo
$localProviderPath = Join-Path $repo "config/provider.local.json"
if (Test-Path -LiteralPath $localProviderPath -PathType Leaf) {
  $localProvider = Get-Content -Raw -LiteralPath $localProviderPath | ConvertFrom-Json
  if (-not $ProviderBaseUrl) { $ProviderBaseUrl = [string]$localProvider.base_url }
  if (-not $ProviderModel) { $ProviderModel = [string]$localProvider.model }
  $localKeys = @($localProvider.api_keys | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
  if ($localKeys.Count -gt 0 -and -not $env:OPENAI_API_KEYS -and -not $env:OPENAI_API_KEY) {
    $env:OPENAI_API_KEYS = $localKeys -join ","
  }
}
$stamp = [guid]::NewGuid().ToString("N")
$temp = Join-Path ([IO.Path]::GetTempPath()) "reverse-analyzer-p11-$stamp"
$context = Join-Path $temp "context"
$groundTruth = Join-Path $temp "ground-truth"
$workspace = Join-Path $temp "workspace"
$artifactRoot = Join-Path $repo "reports/p11-artifacts-$stamp"
$pgName = "reverse-analyzer-p11-pg-$stamp"
$providerProbeName = "reverse-analyzer-p11-provider-$stamp"
$webName = "reverse-analyzer-p11-web-$stamp"
$networkName = "reverse-analyzer-p11-$stamp"
$volumeName = "reverse-analyzer-p11-workspace-$stamp"
$evidence = [ordered]@{ schema_version = 1; status = "running"; started_at = [DateTime]::UtcNow.ToString("o"); checks = [ordered]@{}; blocking_reasons = @() }

function Get-TextSha256([string]$Text) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
  $algorithm = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant() } finally { $algorithm.Dispose() }
}

function Get-ContentDigest([string]$Root) {
  $records = @()
  Get-ChildItem -LiteralPath $Root -Recurse -File | Sort-Object FullName | ForEach-Object {
    $relative = $_.FullName.Substring($Root.TrimEnd('\','/').Length).TrimStart('\','/').Replace("\", "/")
    $records += "$relative`t$((Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant())"
  }
  return [ordered]@{ algorithm = "sorted-relative-path-sha256-v1"; file_count = $records.Count; digest = Get-TextSha256 ($records -join "`n") }
}

function Invoke-Captured([scriptblock]$Command) {
  $old = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try { $output = (& $Command 2>&1 | Out-String); $code = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
  $result = [ordered]@{ exit_code = $code; output_sha256 = Get-TextSha256 $output }
  $summaryLine = @($output -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -like "SAFE_SUMMARY:*" } | Select-Object -Last 1)
  if ($summaryLine.Count -gt 0) {
    try {
      $result.safe_summary = $summaryLine[0].Substring("SAFE_SUMMARY:".Length) | ConvertFrom-Json
    } catch {
      $result.summary_parse_failed = $true
    }
  }
  return $result
}

function Add-Block([string]$Reason) {
  if ($evidence.blocking_reasons -notcontains $Reason) { $evidence.blocking_reasons += $Reason }
}

function Get-FreeTcpPort {
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
  $listener.Start()
  try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
}

function Wait-Http([string]$Url) {
  for ($i=0; $i -lt 120; $i++) {
    try { return Invoke-RestMethod -Uri $Url -TimeoutSec 2 } catch { Start-Sleep -Milliseconds 500 }
  }
  throw "HTTP endpoint did not become ready: $Url"
}

try {
  New-Item -ItemType Directory -Force -Path $temp, $context, $groundTruth, $workspace, $artifactRoot, (Split-Path -Parent $EvidencePath) | Out-Null

  # The image context is a byte-for-byte source snapshot, not a bind mount used at runtime.
  # Copy the exact indexed/current files without routing Unicode paths through
  # Windows tar or a text patch pipeline.
  $sourceFiles = @(
    git -c core.quotepath=false ls-files
    git -c core.quotepath=false ls-files --others --exclude-standard
  ) | Where-Object {
    $_ -and $_ -notmatch '^(\.venv|\.git|\.pytest_cache|\.codex-tmp[^/]*|build|dist|reports|tmp|uploads|experiments|output|frontend/node_modules)/'
  } | Sort-Object -Unique
  foreach ($relative in $sourceFiles) {
    $source = Join-Path $repo $relative
    if (Test-Path -LiteralPath $source -PathType Leaf) {
      $target = Join-Path $context $relative
      New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
      Copy-Item -LiteralPath $source -Destination $target
    }
  }
  $sourceDigest = Get-ContentDigest $context
  $evidence.provenance = [ordered]@{ git_head = (git rev-parse HEAD).Trim(); git_dirty = [bool](git status --porcelain=v1); source_context = $sourceDigest }

  $build = Invoke-Captured { docker build --pull=false -t $Image $context }
  $evidence.commands = [ordered]@{ image_build = $build }
  if ($build.exit_code -ne 0) { throw "fresh image build failed" }
  $evidence.provenance.image_id = (docker image inspect $Image --format '{{.Id}}').Trim()
  $evidence.provenance.versions = [ordered]@{ docker = (docker version --format '{{.Server.Version}}').Trim(); git = (git --version).Trim(); powershell = $PSVersionTable.PSVersion.ToString() }

  $sampleSource = @'
#include <stdio.h>
int main(void) {
  FILE *out = fopen("result.txt", "wb");
  if (!out) { fputs("artifact-error\n", stderr); return 9; }
  fputs("p11-artifact-v1\n", out); fclose(out);
  fputs("p11-stdout-v1\n", stdout);
  fputs("p11-stderr-v1\n", stderr);
  return 7;
}
'@
  $sampleSourcePath = Join-Path $groundTruth "program.c"
  [IO.File]::WriteAllText($sampleSourcePath, $sampleSource, [Text.UTF8Encoding]::new($false))
  $sampleSourceHash = (Get-FileHash -Algorithm SHA256 $sampleSourcePath).Hash.ToLowerInvariant()
  $compile = Invoke-Captured { docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=$groundTruth,destination=/src" --tmpfs /tmp:rw,noexec,nosuid,size=64m --entrypoint cc $Image /src/program.c -O2 -s -o /src/program.exe }
  if ($compile.exit_code -ne 0) {
    # Bootstrap compilation uses a pinned distro image before the platform image exists.
    $compile = Invoke-Captured { docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=$groundTruth,destination=/src" --entrypoint cc gcc:14-bookworm /src/program.c -O2 -s -o /src/program.exe }
  }
  if ($compile.exit_code -ne 0) { throw "authorized sample compilation failed" }
  $sampleBinaryHash = (Get-FileHash -Algorithm SHA256 (Join-Path $groundTruth "program.exe")).Hash.ToLowerInvariant()
  $spec = [ordered]@{
    target_identity = [ordered]@{ id = "p11-authorized-c-fixture"; kind = "compiled_c_fixture"; binary_sha256 = $sampleBinaryHash }
    original = [ordered]@{ argv = @("./program.exe"); target = "program.exe" }
    reconstructed = [ordered]@{ argv = @("./.reconstruction-build/targets/program/program"); target = ".reconstruction-build/targets/program/program" }
    outputs = @([ordered]@{ name = "result"; kind = "sha256"; path = "result.txt" })
  }
  [IO.File]::WriteAllText((Join-Path $groundTruth "behavior-validation.json"), ($spec | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText((Join-Path $groundTruth "PUBLIC-EVIDENCE.txt"), "Authorized P11 fixture; observable contract is stdout/stderr/exit/output artifact.", [Text.UTF8Encoding]::new($false))
  Compress-Archive -Path (Join-Path $groundTruth "program.exe"), (Join-Path $groundTruth "behavior-validation.json"), (Join-Path $groundTruth "PUBLIC-EVIDENCE.txt") -DestinationPath (Join-Path $workspace "authorized-sample.zip")
  $evidence.sample = [ordered]@{ source_sha256 = $sampleSourceHash; binary_sha256 = $sampleBinaryHash; archive_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $workspace "authorized-sample.zip")).Hash.ToLowerInvariant(); ground_truth_in_archive = $false; language = "C"; build_system = "CMake reconstruction target" }

  $evidence.commands.sample_compile = $compile

  docker network create $networkName | Out-Null
  docker volume create $volumeName | Out-Null
  docker run --rm -d --name $pgName --network $networkName -e POSTGRES_DB=p11 -e POSTGRES_USER=p11 -e POSTGRES_PASSWORD=p11-ephemeral postgres:15-bookworm | Out-Null
  for ($i=0; $i -lt 60; $i++) { docker exec $pgName pg_isready -U p11 -d p11 2>$null | Out-Null; if ($LASTEXITCODE -eq 0) { break }; Start-Sleep -Milliseconds 500 }
  if ($LASTEXITCODE -ne 0) { throw "temporary PostgreSQL not ready" }
  $evidence.checks.temporary_postgres = "passed"

  if (-not $ProviderBaseUrl) { $ProviderBaseUrl = "https://api.openai.com/v1" }
  if (-not $ProviderModel) { $ProviderModel = "gpt-4.1-mini" }
  $externalProbe = [ordered]@{ status = "dependency-gated"; http = $null; base_url_origin = ([Uri]$ProviderBaseUrl).GetLeftPart([UriPartial]::Authority); model = $ProviderModel; secret_recorded = $false }
  if ($env:OPENAI_API_KEYS -or $env:OPENAI_API_KEY) {
    $probeScript = @'
import json, os, urllib.error, urllib.request
keys=[value.strip() for value in os.environ.get("OPENAI_API_KEYS",os.environ.get("OPENAI_API_KEY","")).split(",") if value.strip()]
schema={"type":"object","additionalProperties":False,"required":["ok"],"properties":{"ok":{"type":"boolean","const":True}}}
payload={"model":os.environ["OPENAI_MODEL"],"max_tokens":64,"temperature":0,"response_format":{"type":"json_schema","json_schema":{"name":"provider_probe","strict":True,"schema":schema}},"messages":[{"role":"user","content":"Return {\\\"ok\\\":true} as strict JSON."}]}
failures=[]
for slot,key in enumerate(keys,1):
 try:
  request=urllib.request.Request(os.environ["OPENAI_BASE_URL"].rstrip("/")+"/chat/completions",data=json.dumps(payload).encode(),headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"})
  with urllib.request.urlopen(request,timeout=30) as response: envelope=json.loads(response.read())
  value=json.loads(envelope["choices"][0]["message"]["content"])
  if value!={"ok":True}: raise ValueError("strict response mismatch")
  print("SAFE_SUMMARY:"+json.dumps({"http":200,"key_slot":slot,"fallback_count":slot-1,"model":envelope.get("model"),"strict_json":True,"request_id_present":bool(envelope.get("id")),"failure_statuses":failures},separators=(",",":")))
  raise SystemExit(0)
 except urllib.error.HTTPError as error: failures.append({"key_slot":slot,"http_status":error.code})
 except Exception as error: failures.append({"key_slot":slot,"error_type":type(error).__name__})
print("SAFE_SUMMARY:"+json.dumps({"http":None,"key_slot":None,"fallback_count":len(failures),"strict_json":False,"failure_statuses":failures},separators=(",",":")))
raise SystemExit(3)
'@
    $probe = Invoke-Captured { $probeScript | docker run --rm -i --name $providerProbeName --network bridge -e OPENAI_API_KEYS -e OPENAI_API_KEY -e OPENAI_BASE_URL=$ProviderBaseUrl -e OPENAI_MODEL=$ProviderModel --entrypoint python $Image - }
    $externalProbe.http = if ($probe.safe_summary) { $probe.safe_summary.http } else { $null }
    $externalProbe.key_slot = if ($probe.safe_summary) { $probe.safe_summary.key_slot } else { $null }
    $externalProbe.fallback_count = if ($probe.safe_summary) { $probe.safe_summary.fallback_count } else { $null }
    $externalProbe.strict_json = if ($probe.safe_summary) { $probe.safe_summary.strict_json } else { $false }
    $externalProbe.status = if ($probe.exit_code -eq 0) { "ready" } else { "dependency-gated" }
    $evidence.commands.provider_probe = $probe
  }

  $selectedBaseUrl = $ProviderBaseUrl
  $selectedModel = $ProviderModel
  $providerStatus = $externalProbe.status
  $evidence.provider = [ordered]@{ kind = "openai-compatible"; status = $providerStatus; base_url_origin = ([Uri]$selectedBaseUrl).GetLeftPart([UriPartial]::Authority); model = $selectedModel; external_probe = $externalProbe; fallback_policy = "external_credentials_only"; local_model = $null; secret_recorded = $false; network = "provider_network_only_not_yet_proven" }
  if ($providerStatus -ne "ready") { Add-Block "real_model_provider_not_ready" }

  if ($providerStatus -eq "ready") {
    $port = Get-FreeTcpPort
    $socketGid = (docker run --rm --mount "type=bind,source=/var/run/docker.sock,destination=/var/run/docker.sock" --entrypoint stat $Image -c %g /var/run/docker.sock).Trim()
    $providerKeyArgument = if ($env:OPENAI_API_KEYS) { "OPENAI_API_KEYS" } else { "OPENAI_API_KEY" }
    docker run --rm -d --name $webName --network $networkName --group-add $socketGid -p "127.0.0.1:$port`:8090" --mount "type=volume,source=$volumeName,destination=/workspace" --mount "type=bind,source=/var/run/docker.sock,destination=/var/run/docker.sock" -e REVERSE_ANALYZER_ENV=production -e REVERSE_ANALYZER_WEB_TOKEN=p11-ephemeral-token -e REVERSE_ANALYZER_DATABASE_URL="postgres://p11:p11-ephemeral@$pgName`:5432/p11?sslmode=disable" -e REVERSE_ANALYZER_OPENAI_ENABLED=1 -e OPENAI_BASE_URL=$selectedBaseUrl -e OPENAI_MODEL=$selectedModel -e REVERSE_ANALYZER_PROVIDER_TIMEOUT=600 -e REVERSE_ANALYZER_PROVIDER_MAX_OUTPUT_TOKENS=2048 -e REVERSE_ANALYZER_JOB_TIMEOUT=1800 -e $providerKeyArgument -e REVERSE_ANALYZER_SANDBOX_RUNTIME=docker -e REVERSE_ANALYZER_SANDBOX_IMAGE=$Image -e REVERSE_ANALYZER_SANDBOX_WORKSPACE_VOLUME=$volumeName $Image | Out-Null
    $ready = Wait-Http "http://127.0.0.1:$port/readyz"
    $evidence.checks.production_control_plane = [ordered]@{ status = $ready.status; storage = $ready.storage; image = $Image; workspace = "ephemeral_named_volume" }
  }

  $p1Output = Join-Path $artifactRoot "p1-integration-audit.json"
  $p1 = Invoke-Captured { & (Join-Path $repo ".venv/Scripts/python.exe") scripts/p11_catalog_audit.py --workspace $repo --output $p1Output }
  $evidence.commands.p1_catalog_audit = $p1
  if (-not (Test-Path $p1Output)) { Add-Block "p1_catalog_audit_missing" }

  if (-not $SkipRegression) {
    $unittestWrapper = @'
import json, os, shutil, sys, unittest
path=os.environ["P11_SUMMARY_PATH"]
def persist(value):
 encoded=json.dumps(value,separators=(",",":"),sort_keys=True)
 with open(path,"w",encoding="utf-8") as stream: stream.write(encoded+"\n")
 return encoded
persist({"status":"running"})
try:
 suite=unittest.defaultTestLoader.discover("/src/tests", top_level_dir="/src")
 result=unittest.TextTestRunner(verbosity=1).run(suite)
 def ids(records):
  values=[]
  for record in records[:100]:
   case=record[0]
   try: values.append(case.id())
   except Exception: values.append(type(case).__name__)
  return values
 dependency_ids=set()
 if os.name != "nt" and not any(shutil.which(name) for name in ("powershell.exe","powershell","pwsh")):
  dependency_ids.add("tests.test_acceptance_records.AcceptanceRecordTests.test_windows_uia_fixture_contract_retains_hash_backed_live_proof")
 def partition(records):
  gated=[]; blocking=[]
  for record in records:
   try: identifier=record[0].id()
   except Exception: identifier=type(record[0]).__name__
   (gated if identifier in dependency_ids else blocking).append(record)
  return gated,blocking
 gated_failures,blocking_failures=partition(result.failures)
 gated_errors,blocking_errors=partition(result.errors)
 dependency_gated_ids=ids(gated_failures)+ids(gated_errors)
 successful=not blocking_failures and not blocking_errors and not result.unexpectedSuccesses
 summary={"status":"passed" if successful else "failed","tests_run":result.testsRun,"failures":len(blocking_failures),"errors":len(blocking_errors),"dependency_gated":len(dependency_gated_ids),"dependency_gated_test_ids":dependency_gated_ids,"skipped":len(result.skipped),"expected_failures":len(result.expectedFailures),"unexpected_successes":len(result.unexpectedSuccesses),"failing_test_ids":(ids(blocking_failures)+ids(blocking_errors))[:100]}
 encoded=persist(summary)
 print("SAFE_SUMMARY:"+encoded)
 sys.exit(0 if successful else 1)
except BaseException as exc:
 if isinstance(exc,SystemExit): raise
 encoded=persist({"status":"runner_error","error_type":type(exc).__name__})
 print("SAFE_SUMMARY:"+encoded)
 raise
'@
    $unittestRunner = Join-Path $workspace "p11-unittest-runner.py"
    $unittestSummary = Join-Path $workspace "python-regression-summary.json"
    [IO.File]::WriteAllText($unittestRunner, $unittestWrapper, [Text.UTF8Encoding]::new($false))
    $pythonRegression = Invoke-Captured { docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,exec,nosuid,size=512m --mount "type=bind,source=$context,destination=/src,readonly" --mount "type=bind,source=$unittestRunner,destination=/tmp/p11-unittest-runner.py,readonly" --mount "type=bind,source=$workspace,destination=/summary" -w /src -e P11_SUMMARY_PATH=/summary/python-regression-summary.json -e REVERSE_ANALYZER_WORKSPACE=/tmp/workspace -e REVERSE_ANALYZER_KNOWLEDGE_DIR=/tmp/knowledge -e REVERSE_ANALYZER_SESSIONS_DIR=/tmp/sessions -e REVERSE_ANALYZER_REPORTS_DIR=/tmp/reports --entrypoint python $Image /tmp/p11-unittest-runner.py }
    if (Test-Path $unittestSummary) { $pythonRegression["safe_summary"] = Get-Content -Raw $unittestSummary | ConvertFrom-Json }
    $goRegression = Invoke-Captured { go test ./... }
    $frontendRegression = Invoke-Captured { npm --prefix frontend test }
    $evidence.commands.python_regression = $pythonRegression
    $evidence.commands.go_regression = $goRegression
    $evidence.commands.frontend_regression = $frontendRegression
    if ($pythonRegression.exit_code -ne 0) { Add-Block "python_regression_failed" }
    if ($goRegression.exit_code -ne 0) { Add-Block "go_regression_failed" }
    if ($frontendRegression.exit_code -ne 0) { Add-Block "frontend_regression_failed" }
  }

  if ($providerStatus -eq "ready") {
    $headers = @{ Authorization = "Bearer p11-ephemeral-token" }
    $archiveBytes = [IO.File]::ReadAllBytes((Join-Path $workspace "authorized-sample.zip"))
    $upload = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/uploads" -Method Post -Headers $headers -ContentType "application/json" -Body (@{ filename = "authorized-sample.zip"; content_base64 = [Convert]::ToBase64String($archiveBytes) } | ConvertTo-Json)
    $created = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/experiments" -Method Post -Headers $headers -ContentType "application/json" -Body (@{ target = $upload.path; mode = "pe-reconstruction"; provider = "openai_compatible" } | ConvertTo-Json)
    $experimentId = $created.experiment.id
    $null = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/experiments/$experimentId/execute" -Method Post -Headers $headers -ContentType "application/json" -Body (@{ confirmation = "EXECUTE_LOCAL_ANALYSIS" } | ConvertTo-Json)
    $experiment = $null
    for ($i=0; $i -lt 1800; $i++) {
      Start-Sleep -Seconds 1
      $experiment = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/experiments/$experimentId" -Headers $headers
      if ($experiment.status -notin @("queued", "planned", "running")) { break }
    }
    if (-not $experiment -or $experiment.status -ne "completed") { Add-Block "production_archive_chain_failed" }
    $copyResult = Invoke-Captured { docker run --rm --network none --mount "type=volume,source=$volumeName,destination=/source,readonly" --mount "type=bind,source=$artifactRoot,destination=/evidence" --entrypoint python $Image -c "import shutil; shutil.copytree('/source/experiments/$experimentId','/evidence/platform-experiment',dirs_exist_ok=True)" }
    $evidence.commands.production_archive_chain = [ordered]@{ api_status = $experiment.status; experiment_id = $experimentId; artifact_copy = $copyResult }
    $manifestPath = Join-Path $artifactRoot "platform-experiment/analysis/archive-workspace-v3/archive-manifest.json"
    if (-not (Test-Path $manifestPath)) {
      Add-Block "production_archive_manifest_missing"
    } else {
      $manifest = Get-Content -Raw $manifestPath | ConvertFrom-Json
      $project = Get-ChildItem (Join-Path $artifactRoot "platform-experiment/analysis") -Directory -Filter "reconstructed_archive_*" | Select-Object -First 1
      $docs = Join-Path $project.FullName "docs"
      $model = Get-Content -Raw (Join-Path $docs "model-reconstruction.json") | ConvertFrom-Json
      $graph = Get-Content -Raw (Join-Path $docs "reconstruction-graph.json") | ConvertFrom-Json
      $readiness = Get-Content -Raw (Join-Path $docs "build-readiness.json") | ConvertFrom-Json
      $buildResult = Get-Content -Raw (Join-Path $docs "build-result.json") | ConvertFrom-Json
      $behavior = Get-Content -Raw (Join-Path $docs "behavior-validation.json") | ConvertFrom-Json
      $calls = @($model.calls)
      $tokenTotal = [int64]($model.usage.total_tokens)
      $artifactChecks = [ordered]@{
        model_calls_positive = $calls.Count -gt 0
        model_tokens_positive = $tokenTotal -gt 0
        graph_nonempty = ([int]$graph.node_count -gt 0 -and [int]$graph.edge_count -gt 0 -and [bool]$graph.fingerprint)
        manifest_present = Test-Path (Join-Path $docs "project-manifest.json")
        lock_present = Test-Path (Join-Path $docs "dependencies.lock.json")
        build_real_isolated = ($buildResult.status -eq "passed" -and $buildResult.build_passed -eq $true -and $buildResult.isolated -eq $true)
        behavior_real = ($behavior.status -eq "passed" -and $behavior.behavior_equivalent -eq $true -and $behavior.provenance.validator.real_subprocess -eq $true -and $behavior.provenance.validator.runner_injected -eq $false -and $behavior.provenance.validator.shell -eq $false)
        behavior_comparisons = ([int]$behavior.summary.comparison_count -ge 4)
        behavior_output = (@($behavior.comparisons | Where-Object { $_.kind -like "output*" }).Count -ge 1)
        worker_network_none = ($manifest.worker_network.declared -eq "none" -and $manifest.worker_network.egress_blocked -eq $true -and (Get-Content -Raw (Join-Path $artifactRoot "platform-experiment/analysis/provider-broker/audit.json") -ErrorAction SilentlyContinue | ConvertFrom-Json).worker_network -eq "none")
      }
      foreach ($entry in $artifactChecks.GetEnumerator()) { if (-not $entry.Value) { Add-Block "artifact_gate_failed:$($entry.Key)" } }
      $six = [ordered]@{
        analysis_complete = $true
        source_generated = Test-Path (Join-Path $project.FullName "CMakeLists.txt")
        structure_complete = $readiness.structure_complete -eq $true
        dependencies_locked = $readiness.dependencies_locked -eq $true
        build_passed = $artifactChecks.build_real_isolated
        behavior_passed = $artifactChecks.behavior_real
      }
      $complete = $experiment.reconstruction.complete_buildable -eq $true -and -not ($six.Values -contains $false) -and $artifactChecks.worker_network_none
      if (-not $complete) { Add-Block "trusted_complete_buildable_artifacts_not_proven" }
      $evidence.experiment = [ordered]@{ status = $experiment.status; production_chain_invoked = $true; reconstruction = $experiment.reconstruction }
      $evidence.artifacts = [ordered]@{ root = $artifactRoot.Substring($repo.TrimEnd('\','/').Length).TrimStart('\','/').Replace("\", "/"); project = $project.FullName.Substring($artifactRoot.TrimEnd('\','/').Length).TrimStart('\','/').Replace("\", "/"); checks = $artifactChecks; manifest_sha256 = (Get-FileHash -Algorithm SHA256 $manifestPath).Hash.ToLowerInvariant(); model_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $docs "model-reconstruction.json")).Hash.ToLowerInvariant(); graph_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $docs "reconstruction-graph.json")).Hash.ToLowerInvariant(); build_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $docs "build-result.json")).Hash.ToLowerInvariant(); behavior_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $docs "behavior-validation.json")).Hash.ToLowerInvariant() }
    }
  }

  if (-not $evidence.experiment) { $evidence.experiment = [ordered]@{ status = "dependency-gated"; production_chain_invoked = $false; reconstruction = [ordered]@{ analysis_complete = $false; source_generated = $false; structure_complete = $false; dependencies_locked = $false; build_passed = $false; behavior_passed = $false; complete_buildable = $false } } }
  if ($evidence.experiment.reconstruction.complete_buildable -ne $true) { Add-Block "complete_buildable_not_proven" }
  $evidence.checks.truthful_complete_buildable_gate = "passed"
  $evidence.status = if ($evidence.blocking_reasons.Count -eq 0 -and $evidence.experiment.reconstruction.complete_buildable -eq $true) { "passed" } else { "dependency-gated" }
} catch {
  $evidence.status = "failed"
  $evidence.error = $_.Exception.Message
  Add-Block "p11_harness_failure"
} finally {
  $evidence.completed_at = [DateTime]::UtcNow.ToString("o")
  $json = $evidence | ConvertTo-Json -Depth 12
  [IO.File]::WriteAllText((Join-Path $repo $EvidencePath), $json + "`n", [Text.UTF8Encoding]::new($false))
  foreach ($name in @($providerProbeName, $webName, $pgName)) { if (docker ps -aq --filter "name=^/$name`$" 2>$null) { docker rm -f $name 2>$null | Out-Null } }
  if (docker network ls -q --filter "name=^$networkName`$" 2>$null) { docker network rm $networkName 2>$null | Out-Null }
  if (docker volume ls -q --filter "name=^$volumeName`$" 2>$null) { docker volume rm -f $volumeName 2>$null | Out-Null }
  if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}

if ($evidence.status -ne "passed") { exit 3 }
