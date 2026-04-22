# Generate a self-signed TLS certificate for localhost DIMSE testing.
#
# Run once. Produces fodicom-harness.pfx in this directory. The .pfx
# password defaults to "fuzz" -- hardcoded because this cert is only
# ever used locally against this harness. Rotate manually if needed.
#
# Usage (from PowerShell):
#   cd targets/fodicom-network-harness
#   pwsh ./gen-cert.ps1

$ErrorActionPreference = "Stop"

$certPath = Join-Path $PSScriptRoot "fodicom-harness.pfx"
$password = ConvertTo-SecureString -String "fuzz" -Force -AsPlainText

$cert = New-SelfSignedCertificate `
    -Subject "CN=localhost" `
    -DnsName "localhost" `
    -CertStoreLocation "cert:\CurrentUser\My" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(1)

Export-PfxCertificate -Cert $cert -FilePath $certPath -Password $password | Out-Null
Remove-Item -Path "cert:\CurrentUser\My\$($cert.Thumbprint)"

Write-Host "Wrote $certPath (password: fuzz)"
