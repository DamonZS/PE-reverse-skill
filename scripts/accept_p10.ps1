param(
  [string]$Image = "reverse-analyzer:p10-acceptance",
  [string]$EvidencePath = "reports/p10-acceptance.json"
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repo
$stamp = [guid]::NewGuid().ToString("N")
$pgName = "reverse-analyzer-p10-pg-$stamp"
$webName = "reverse-analyzer-p10-web-$stamp"
$port = 0
$pgPort = 0
$temp = Join-Path ([System.IO.Path]::GetTempPath()) "reverse-analyzer-p10-$stamp"
$evidence = [ordered]@{ status = "running"; started_at = [DateTime]::UtcNow.ToString("o"); checks = [ordered]@{}; commands = [ordered]@{} }

function Get-FreeTcpPort {
  $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
  $listener.Start()
  try { return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
}

function Get-TextSha256([string]$Text) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
  $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
  return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
}

function Get-WorkspaceContentDigest {
  $headTree = (git rev-parse 'HEAD^{tree}').Trim()
  $trackedDiff = (git diff --binary HEAD | Out-String)
  $trackedFiles = @((git -c core.quotepath=false diff --name-only HEAD) | Where-Object { $_ })
  $evidenceRelative = ($EvidencePath -replace '\\','/').TrimStart('./')
  $exclusions = @(
    [ordered]@{ pattern = '^' + [Regex]::Escape($evidenceRelative) + '$'; reason = 'acceptance evidence is written after the before/after comparison'; excluded_file_count = 0 },
    [ordered]@{ pattern = '^frontend/dist/'; reason = 'generated frontend production build'; excluded_file_count = 0 },
    [ordered]@{ pattern = '^(frontend/)?node_modules/'; reason = 'installed package dependencies, reproducible from lockfiles'; excluded_file_count = 0 },
    [ordered]@{ pattern = '^\.venv/'; reason = 'installed Python environment, reproducible from dependency metadata'; excluded_file_count = 0 },
    [ordered]@{ pattern = '(^|/)__pycache__/|\.py[co]$|^\.pytest_cache/'; reason = 'generated Python bytecode and test cache'; excluded_file_count = 0 },
    [ordered]@{ pattern = '^(build|dist)/|\.egg-info/'; reason = 'generated package build output'; excluded_file_count = 0 },
    [ordered]@{ pattern = '^\.reverse_analyzer/'; reason = 'mutable platform runtime state, not source input'; excluded_file_count = 0 },
    [ordered]@{ pattern = '^reports/'; reason = 'generated machine-readable acceptance and analysis reports'; excluded_file_count = 0 },
    [ordered]@{ pattern = '^\.codex-tmp'; reason = 'generated temporary release and test output'; excluded_file_count = 0 },
    [ordered]@{ pattern = '^\.codegraph/'; reason = 'generated code graph database and daemon state'; excluded_file_count = 0 },
    [ordered]@{ pattern = '^(\.workbuddy|tmp|\.playwright-cli)/'; reason = 'generated tool scratch and browser state'; excluded_file_count = 0 },
    [ordered]@{ pattern = '^(experiments|uploads|output)/'; reason = 'mutable user workload and runtime output, not source input'; excluded_file_count = 0 }
  )
  $candidates = @(
    (git -c core.quotepath=false ls-files --others --exclude-standard)
    (git -c core.quotepath=false ls-files --others --ignored --exclude-standard)
  ) | Where-Object { $_ } | Sort-Object -Unique
  $untracked = @()
  foreach ($relative in $candidates) {
    $excluded = $false
    foreach ($rule in $exclusions) {
      if ($relative -match $rule.pattern) {
        $rule['excluded_file_count'] = [int]$rule['excluded_file_count'] + 1
        $excluded = $true
        break
      }
    }
    if (-not $excluded) { $untracked += $relative }
  }
  $untrackedRecords = @()
  foreach ($relative in $untracked) {
    $full = Join-Path $repo ($relative -replace '/', [IO.Path]::DirectorySeparatorChar)
    if (Test-Path -LiteralPath $full -PathType Leaf) {
      $untrackedRecords += "$relative`t$((Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash.ToLowerInvariant())"
    }
  }
  $material = "algorithm=git-tree+binary-diff+all-untracked-sha256-v2`nhead_tree=$headTree`ntracked_diff_sha256=$(Get-TextSha256 $trackedDiff)`n" + ($untrackedRecords -join "`n")
  return [ordered]@{
    algorithm = "git-tree+binary-diff+all-untracked-sha256-v2"
    digest = Get-TextSha256 $material
    head_tree = $headTree
    tracked_diff_sha256 = Get-TextSha256 $trackedDiff
    tracked_changed_file_count = $trackedFiles.Count
    untracked_file_count = $untrackedRecords.Count
    file_count = $trackedFiles.Count + $untrackedRecords.Count
    exclusions = $exclusions
  }
}

function Test-UntrackedContentChangesDigest {
  $probeRelative = ".p10-digest-probe-$stamp.txt"
  $probe = Join-Path $repo $probeRelative
  try {
    Set-Content -NoNewline -Encoding utf8 -LiteralPath $probe -Value "before"
    $before = Get-WorkspaceContentDigest
    Set-Content -NoNewline -Encoding utf8 -LiteralPath $probe -Value "after"
    $after = Get-WorkspaceContentDigest
    if ($before.digest -eq $after.digest) { throw "included untracked content did not change workspace digest" }
  } finally {
    if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Force }
  }
}

function Wait-Postgres {
  for ($i = 0; $i -lt 40; $i++) {
    $ready = docker exec $pgName pg_isready -U reverse_test -d reverse_analyzer_test 2>$null
    if ($LASTEXITCODE -eq 0 -and $ready -match "accepting") { return }
    Start-Sleep -Milliseconds 500
  }
  throw "temporary PostgreSQL did not become ready"
}

function Wait-Ready {
  for ($i = 0; $i -lt 40; $i++) {
    try {
      $result = Invoke-RestMethod "http://127.0.0.1:$port/readyz" -TimeoutSec 2
      if ($result.status -eq "ready") { return $result }
    } catch {}
    Start-Sleep -Milliseconds 500
  }
  throw "production container did not become ready"
}

try {
  Test-UntrackedContentChangesDigest
  $evidence.checks.dirty_content_untracked_change_detection = "passed"
  $dirtyStart = Get-WorkspaceContentDigest
  $port = Get-FreeTcpPort
  $pgPort = Get-FreeTcpPort
  New-Item -ItemType Directory -Force -Path $temp, (Split-Path -Parent $EvidencePath) | Out-Null
  $workspace = Join-Path $temp "workspace"
  $backup = Join-Path $temp "backup"
  $restore = Join-Path $temp "restore"
  $secrets = Join-Path $temp "secrets"
  New-Item -ItemType Directory -Force -Path $workspace, $backup, $restore, $secrets | Out-Null
  $passwordFile = Join-Path $secrets "postgres-password"
  $pgpassFile = Join-Path $secrets "pgpass"
  $tokenFile = Join-Path $secrets "web-token"
  Set-Content -NoNewline -Path $passwordFile -Value "p10-acceptance-password"
  Set-Content -NoNewline -Path $pgpassFile -Value "127.0.0.1:$pgPort`:*:reverse_test:p10-acceptance-password`nhost.docker.internal:$pgPort`:*:reverse_test:p10-acceptance-password"
  Set-Content -NoNewline -Path $tokenFile -Value "p10-acceptance-token"

  $savedErrorPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  $buildOutput = (docker build -t $Image . 2>&1 | Out-String)
  $buildExit = $LASTEXITCODE
  $ErrorActionPreference = $savedErrorPreference
  $evidence.commands.image_build = @{ exit_code = $buildExit; output_sha256 = Get-TextSha256 $buildOutput }
  if ($buildExit -ne 0) { throw "image build failed" }
  $evidence.checks.image_build = "passed"
  docker run --rm -d --name $pgName -e POSTGRES_DB=reverse_analyzer_test -e POSTGRES_USER=reverse_test -e POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password --mount "type=bind,source=$passwordFile,destination=/run/secrets/postgres_password,readonly" -p "127.0.0.1:$pgPort`:5432" postgres:15-bookworm | Out-Null
  Wait-Postgres
  # lib/pq on the Windows acceptance host does not honor the container-oriented
  # PGPASSFILE path. This value exists only in the child test process environment
  # and is never copied into the machine-readable evidence.
  $databaseUrl = "postgres://reverse_test:p10-acceptance-password@127.0.0.1:$pgPort/reverse_analyzer_test?sslmode=disable"
  $env:REVERSE_ANALYZER_DATABASE_URL = $databaseUrl
  $env:PGPASSFILE = $pgpassFile
  $goOutput = (go test ./cmd/reverse-analyzer-server -run TestPostgreSQL -count=1 2>&1 | Out-String)
  $evidence.commands.postgres_tests = @{ exit_code = $LASTEXITCODE; output_sha256 = Get-TextSha256 $goOutput }
  if ($LASTEXITCODE -ne 0) { throw "PostgreSQL integration tests failed: $goOutput" }
  Remove-Item Env:REVERSE_ANALYZER_DATABASE_URL
  Remove-Item Env:PGPASSFILE
  $evidence.checks.postgres_migrations_isolation_recovery = @{
    status = "passed"
    migration_count = 8
    audit_outbox_maintenance_guard = "deliverAuditOutbox delivered_at update rejected while frozen"
  }
  docker exec $pgName createdb -U reverse_test reverse_analyzer_restore

  docker run --rm -d --name $webName -p "127.0.0.1:$port`:8090" --mount "type=bind,source=$workspace,destination=/workspace" --mount "type=bind,source=$passwordFile,destination=/run/secrets/postgres_password,readonly" --mount "type=bind,source=$tokenFile,destination=/run/secrets/web_token,readonly" -e REVERSE_ANALYZER_ENV=production -e REVERSE_ANALYZER_WEB_TOKEN_FILE=/run/secrets/web_token -e REVERSE_ANALYZER_POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password -e REVERSE_ANALYZER_POSTGRES_HOST=host.docker.internal -e REVERSE_ANALYZER_POSTGRES_PORT=$pgPort -e REVERSE_ANALYZER_POSTGRES_DB=reverse_analyzer_test -e REVERSE_ANALYZER_POSTGRES_USER=reverse_test $Image | Out-Null
  $ready = Wait-Ready
  $health = Invoke-RestMethod "http://127.0.0.1:$port/healthz" -TimeoutSec 3
  $evidence.checks.production_health = @{ health = $health.status; ready = $ready.status; storage = $ready.storage }

  $otherTenantSecret = "other-workspace-secret-$stamp"
  docker exec $pgName psql -U reverse_test -d reverse_analyzer_test -v ON_ERROR_STOP=1 -c "INSERT INTO workspaces(id,name) VALUES('/other-workspace','other'); INSERT INTO experiments(id,workspace_id,status,created_at,updated_at,payload) VALUES('other-$stamp','/other-workspace','queued',now(),now(),jsonb_build_object('secret','$otherTenantSecret'));" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "two-workspace fixture creation failed" }

  $backupOutput = (docker run --rm --entrypoint reverse-analyzer-backup --mount "type=bind,source=$workspace,destination=/workspace-data,readonly" --mount "type=bind,source=$backup,destination=/backup" --mount "type=bind,source=$pgpassFile,destination=/run/secrets/pgpass,readonly" -e PGPASSFILE=/run/secrets/pgpass $Image backup --workspace /workspace-data --workspace-id /workspace --output /backup/snapshot --database-url "postgres://reverse_test@host.docker.internal:$pgPort/reverse_analyzer_test?sslmode=disable" 2>&1 | Out-String)
  $evidence.commands.tenant_backup = @{ exit_code = $LASTEXITCODE; output_sha256 = Get-TextSha256 $backupOutput }
  if ($LASTEXITCODE -ne 0) { throw "tenant backup failed with exit code $LASTEXITCODE" }
  $secretFound = $false
  Get-ChildItem (Join-Path $backup "snapshot") -Recurse -File | ForEach-Object {
    $content = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($_.FullName))
    if ($content.Contains($otherTenantSecret)) { $secretFound = $true }
  }
  if ($secretFound) { throw "another workspace secret leaked into tenant backup bundle" }
  $restoreOutput = (docker run --rm --entrypoint reverse-analyzer-backup --mount "type=bind,source=$restore,destination=/restore" --mount "type=bind,source=$backup,destination=/backup,readonly" --mount "type=bind,source=$pgpassFile,destination=/run/secrets/pgpass,readonly" -e PGPASSFILE=/run/secrets/pgpass $Image restore --workspace /restore/workspace --input /backup/snapshot --staging-database-url "postgres://reverse_test@host.docker.internal:$pgPort/reverse_analyzer_restore?sslmode=disable" --confirm RESTORE_PLATFORM_BACKUP 2>&1 | Out-String)
  $evidence.commands.tenant_restore = @{ exit_code = $LASTEXITCODE; output_sha256 = Get-TextSha256 $restoreOutput }
  if ($LASTEXITCODE -ne 0) { throw "tenant restore failed with exit code $LASTEXITCODE" }
  $migrations = docker exec $pgName psql -U reverse_test -d reverse_analyzer_restore -tAc "SELECT count(*) FROM schema_migrations"
  if ($migrations.Trim() -ne "8") { throw "restore migration verification failed: $migrations" }
  $otherRows = docker exec $pgName psql -U reverse_test -d reverse_analyzer_restore -tAc "SELECT count(*) FROM workspaces WHERE id='/other-workspace'"
  $restoredRows = docker exec $pgName psql -U reverse_test -d reverse_analyzer_restore -tAc "SELECT count(*) FROM workspaces WHERE id='/workspace'"
  if ($otherRows.Trim() -ne "0" -or $restoredRows.Trim() -ne "1") { throw "workspace isolation verification failed: restored=$restoredRows other=$otherRows" }
  $evidence.checks.backup_restore_staging = "passed"
  $evidence.checks.two_workspace_isolation = @{ restored_workspace_rows = 1; other_workspace_rows = 0; other_secret_absent_from_bundle = $true }

  # Duplicate the final migration version so the second ledger INSERT fails
  # after tenant COPY statements have run. The single restore transaction must
  # roll back both the tenant rows and every schema_migrations row.
  docker exec $pgName createdb -U reverse_test reverse_analyzer_restore_fault
  if ($LASTEXITCODE -ne 0) { throw "fault-injection staging database creation failed" }
  $faultBundle = Join-Path $temp "fault-backup"
  New-Item -ItemType Directory -Force -Path $faultBundle | Out-Null
  Copy-Item -Recurse -Force -Path (Join-Path $backup 'snapshot\*') -Destination $faultBundle
  $faultManifestPath = Join-Path $faultBundle 'manifest.json'
  $faultManifest = Get-Content -Raw $faultManifestPath | ConvertFrom-Json
  $faultManifest.migration_versions = @($faultManifest.migration_versions) + @([int]$faultManifest.migration_versions[-1])
  [IO.File]::WriteAllText($faultManifestPath, ($faultManifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
  $savedErrorPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  $faultOutput = (docker run --rm --entrypoint reverse-analyzer-backup --mount "type=bind,source=$restore,destination=/restore" --mount "type=bind,source=$faultBundle,destination=/fault,readonly" --mount "type=bind,source=$pgpassFile,destination=/run/secrets/pgpass,readonly" -e PGPASSFILE=/run/secrets/pgpass $Image restore --workspace /restore/fault-workspace --input /fault --staging-database-url "postgres://reverse_test@host.docker.internal:$pgPort/reverse_analyzer_restore_fault?sslmode=disable" --confirm RESTORE_PLATFORM_BACKUP 2>&1 | Out-String)
  $faultExit = $LASTEXITCODE
  $ErrorActionPreference = $savedErrorPreference
  $evidence.commands.tenant_restore_fault_injection = @{ exit_code = $faultExit; output_sha256 = Get-TextSha256 $faultOutput }
  if ($faultExit -eq 0) { throw "fault-injected tenant restore unexpectedly succeeded" }
  $faultTenantRows = docker exec $pgName psql -U reverse_test -d reverse_analyzer_restore_fault -tAc "SELECT count(*) FROM workspaces"
  $faultMigrationRows = docker exec $pgName psql -U reverse_test -d reverse_analyzer_restore_fault -tAc "SELECT count(*) FROM schema_migrations"
  if ($faultTenantRows.Trim() -ne "0" -or $faultMigrationRows.Trim() -ne "0") {
    throw "fault-injected restore was not atomic: tenant_rows=$faultTenantRows migration_rows=$faultMigrationRows"
  }
  $evidence.checks.restore_transaction_fault_rollback = @{ tenant_rows = 0; migration_rows = 0; injected_failure = "duplicate schema_migrations version" }
  $gitStatus = (git status --porcelain=v1 | Out-String)
  $dirtyEnd = Get-WorkspaceContentDigest
  if ($dirtyStart.digest -ne $dirtyEnd.digest) { throw "workspace content changed during acceptance" }
  $evidence.provenance = [ordered]@{
    git_head = (git rev-parse HEAD).Trim()
    git_dirty = [bool]$gitStatus
    git_dirty_hash = Get-TextSha256 $gitStatus
    dirty_content = $dirtyEnd
    image_id = (docker image inspect $Image --format '{{.Id}}').Trim()
    image_repo_digests = @((docker image inspect $Image --format '{{json .RepoDigests}}' | ConvertFrom-Json))
    backup_manifest_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $backup 'snapshot\manifest.json')).Hash.ToLowerInvariant()
    versions = [ordered]@{ docker = (docker version --format '{{.Server.Version}}').Trim(); go = (go version).Trim(); python = (& .venv\Scripts\python.exe --version 2>&1 | Out-String).Trim(); postgres = (docker exec $pgName postgres --version).Trim() }
    ports = [ordered]@{ web = $port; postgres = $pgPort }
  }
  $evidence.status = "passed"
} catch {
  $evidence.status = "failed"
  $evidence.error = $_.Exception.Message
  throw
} finally {
  $evidence.completed_at = [DateTime]::UtcNow.ToString("o")
  $evidence | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -Path $EvidencePath
  if (docker ps -aq --filter "name=^/$webName`$" 2>$null) { docker rm -f $webName 2>$null | Out-Null }
  if (docker ps -aq --filter "name=^/$pgName`$" 2>$null) { docker rm -f $pgName 2>$null | Out-Null }
  if (Test-Path $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
