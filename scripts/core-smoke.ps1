$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'core-env-load.ps1')
Push-Location $repoRoot
$serverProcess = $null
$binaryRelative = if ($env:OS -eq 'Windows_NT') { '.local/ratchetd.exe' } else { '.local/ratchetd' }
$binary = Join-Path $repoRoot $binaryRelative
try {
    go build -o $binary ./cmd/ratchetd
    if ($LASTEXITCODE -ne 0) { throw 'Core build failed.' }
    & $binary migrate
    if ($LASTEXITCODE -ne 0) { throw 'Migration failed.' }
    $tenant = 'smoke_' + [Guid]::NewGuid().ToString()
    $command = [Guid]::NewGuid().ToString()
    $actor = [Guid]::NewGuid().ToString()
    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath PRD.md).Hash.ToLowerInvariant()
    $recordArgs = @('record-core-evidence','--tenant',$tenant,'--stream','core:smoke','--command-id',$command,'--actor-reference',$actor,'--evidence-sha256',$digest)
    $first = & $binary @recordArgs
    if ($LASTEXITCODE -ne 0) { throw 'Initial append failed.' }
    $second = & $binary @recordArgs
    if ($LASTEXITCODE -ne 0) { throw 'Retry in a new process failed.' }
    if (($first | ConvertFrom-Json).duplicate -or -not ($second | ConvertFrom-Json).duplicate) { throw 'Idempotency evidence failed.' }
    $loaded = & $binary load-stream --tenant $tenant --stream core:smoke
    if ($LASTEXITCODE -ne 0 -or -not $loaded.Contains($digest)) { throw 'Restart read did not match persisted evidence.' }
    $verification = & $binary verify-chain --tenant $tenant
    if ($LASTEXITCODE -ne 0 -or ($verification | ConvertFrom-Json).events_verified -ne 1) { throw 'Chain verification failed.' }
    $startArgs = @{
        FilePath = $binary
        ArgumentList = @('serve','--listen','127.0.0.1:58080')
        PassThru = $true
        RedirectStandardOutput = (Join-Path $repoRoot '.local/health.stdout.log')
        RedirectStandardError = (Join-Path $repoRoot '.local/health.stderr.log')
    }
    if ($env:OS -eq 'Windows_NT') { $startArgs['WindowStyle'] = 'Hidden' }
    $serverProcess = Start-Process @startArgs
    $storageReady = $false
    for ($attempt=0; $attempt -lt 30; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1:58080/readyz/storage'
            if ($response.StatusCode -eq 200) { $storageReady=$true; break }
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $storageReady) { throw 'Storage readiness did not become healthy.' }
    $live = Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1:58080/livez'
    if ($live.StatusCode -ne 200) { throw 'Liveness failed.' }
    try { $null = Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1:58080/readyz'; throw 'Decision readiness must be unavailable in Phase 0.' }
    catch { if (-not $_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne 503) { throw } }
    Write-Output 'PASS: real append, idempotent retry, new-process read, chain verification, liveness, storage readiness, and fail-closed decision readiness.'
} finally {
    if ($serverProcess -and -not $serverProcess.HasExited) { Stop-Process -Id $serverProcess.Id }
    Pop-Location
}
