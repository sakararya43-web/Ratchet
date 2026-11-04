# Creates development-only credentials outside Git. Does not overwrite an existing file.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$localDir = Join-Path $repoRoot '.local'
$envPath = Join-Path $localDir 'core.env'
if (Test-Path -LiteralPath $envPath) { throw 'Local credentials already exist; reusing them requires no regeneration.' }
New-Item -ItemType Directory -Force -Path $localDir | Out-Null
$lines = foreach ($name in @('POSTGRES_PASSWORD', 'RATCHET_MIGRATOR_PASSWORD', 'RATCHET_RUNTIME_PASSWORD', 'RATCHET_PROJECTOR_PASSWORD')) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $value = ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    "$name=$value"
}
[System.IO.File]::WriteAllLines($envPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
Write-Output 'Created .local/core.env. Keep it private and retain it with the local database volume.'
