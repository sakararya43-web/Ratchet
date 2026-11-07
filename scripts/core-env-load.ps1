$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$envPath = Join-Path $repoRoot '.local/core.env'
if (-not (Test-Path -LiteralPath $envPath)) { throw 'Run scripts/core-env.ps1 first.' }
$values = @{}
foreach ($line in [System.IO.File]::ReadAllLines($envPath)) {
    if ($line -and -not $line.StartsWith('#')) {
        $parts = $line.Split('=',2)
        $values[$parts[0]] = $parts[1]
    }
}
$port = if ($values.ContainsKey('RATCHET_POSTGRES_PORT')) { $values['RATCHET_POSTGRES_PORT'] } else { '55434' }
foreach ($role in @('MIGRATOR','RUNTIME','PROJECTOR')) {
    $password = $values["RATCHET_${role}_PASSWORD"]
    if ($password -notmatch '^[a-f0-9]{64}$') { throw 'Expected locally generated hexadecimal credentials.' }
    $user = 'ratchet_' + $role.ToLowerInvariant()
    $dsn = "postgres://${user}:${password}@127.0.0.1:${port}/ratchet?sslmode=disable"
    $name = switch ($role) { 'MIGRATOR' { 'RATCHET_MIGRATION_DSN' } 'RUNTIME' { 'RATCHET_DATABASE_DSN' } 'PROJECTOR' { 'RATCHET_PROJECTOR_DSN' } }
    [Environment]::SetEnvironmentVariable($name,$dsn,'Process')
}
if (-not $env:RATCHET_NATS_URL) {
    # Match this repository's loopback-only Compose publication, not NATS's
    # unrelated default port. Preserve an explicitly selected external broker.
    $env:RATCHET_NATS_URL = 'nats://127.0.0.1:54222'
}
