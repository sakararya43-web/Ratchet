param(
    [ValidateSet('prototype', 'completion-a')]
    [string]$Profile = 'prototype'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$caPath = Join-Path $projectRoot ".local/$Profile/ca.pem"
if (-not (Test-Path -LiteralPath $caPath)) {
    throw "Start the $Profile runtime and export its public CA first."
}

$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caPath)
$constraints = $certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
if ($certificate.Subject -ne 'CN=RATCHET local prototype CA' -or
    $certificate.Subject -ne $certificate.Issuer -or
    $certificate.HasPrivateKey -or -not $constraints.CertificateAuthority -or
    $certificate.NotBefore -gt (Get-Date) -or $certificate.NotAfter -le (Get-Date)) {
    throw 'Expected a currently valid public Ratchet prototype CA.'
}

# Verify the running service against this exact CA before changing user trust.
# No disabled validation callback or certificate exception is used.
$verifyService = @'
import ssl, sys, urllib.request
context = ssl.create_default_context(cafile=sys.argv[1])
with urllib.request.urlopen('https://localhost:8444/readyz', context=context, timeout=10) as response:
    if response.status != 200:
        raise RuntimeError('The selected local HTTPS service is not ready.')
'@
& python -c $verifyService $caPath
if ($LASTEXITCODE -ne 0) { throw 'The running server does not verify against the selected CA.' }

$storePath = "Cert:\CurrentUser\Root\$($certificate.Thumbprint)"
if (-not (Test-Path -LiteralPath $storePath)) {
    Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
}
if (-not (Test-Path -LiteralPath $storePath)) { throw 'The CA was not installed in the current user trust store.' }

$response = Invoke-WebRequest -Uri 'https://localhost:8444/readyz' -UseBasicParsing
if ($response.StatusCode -ne 200) { throw 'Windows HTTPS verification did not succeed.' }
Write-Output "Verified HTTPS: https://localhost:8444 (current-user CA $($certificate.Thumbprint))"
Write-Output 'Open a fresh browser window after the first install. Repeat after explicitly renewing local TLS.'
