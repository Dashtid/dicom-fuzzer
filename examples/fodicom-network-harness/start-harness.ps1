<#
.SYNOPSIS
  One-shot launcher for the fo-dicom network harness.

.DESCRIPTION
  Idempotently builds the harness (only if source is newer than exe, or -Rebuild
  is passed), generates a TLS cert on demand (only if -Tls is requested and no
  pfx exists), and then starts the SCP with the requested port / AE title.

  Defaults match Program.cs (port 11112, AE title FUZZ_SCP). Press Ctrl+C to stop.

.PARAMETER Port
  TCP port to bind. Default 11112.

.PARAMETER AeTitle
  AE title to expose. Default FUZZ_SCP.

.PARAMETER Tls
  Enable TLS. If -TlsPfx isn't given, falls back to ./fodicom-harness.pfx
  (generating it via gen-cert.ps1 if missing).

.PARAMETER TlsPfx
  Path to a PFX file. Ignored unless -Tls is also passed.

.PARAMETER TlsPassword
  Password for the PFX. Defaults to 'fuzz' (the gen-cert.ps1 default).

.PARAMETER Rebuild
  Force a rebuild even if the exe looks current.

.EXAMPLE
  ./start-harness.ps1
  Plain DIMSE on default port 11112.

.EXAMPLE
  ./start-harness.ps1 -Tls
  TLS on 11112 using the local fodicom-harness.pfx.

.EXAMPLE
  ./start-harness.ps1 -Port 11113 -AeTitle MY_SCP -Rebuild
  Force rebuild, custom port and AE title.
#>
[CmdletBinding()]
param(
    [int]$Port = 11112,
    [string]$AeTitle = "FUZZ_SCP",
    [switch]$Tls,
    [string]$TlsPfx,
    [string]$TlsPassword = "fuzz",
    [switch]$Rebuild
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$exe = Join-Path $here "bin\Release\net8.0\win-x64\publish\fodicom-network-harness.exe"
$defaultPfx = Join-Path $here "fodicom-harness.pfx"

# --- Decide whether to rebuild ---
$needBuild = $Rebuild -or -not (Test-Path $exe)
if (-not $needBuild) {
    $exeMtime = (Get-Item $exe).LastWriteTime
    $newestSrc = Get-ChildItem $here -Filter *.cs -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($newestSrc -and $newestSrc.LastWriteTime -gt $exeMtime) {
        Write-Host "[i] $($newestSrc.Name) is newer than exe -- rebuilding."
        $needBuild = $true
    }
}

if ($needBuild) {
    Write-Host "[i] dotnet publish..."
    Push-Location $here
    try {
        dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true |
            Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet publish failed with exit code $LASTEXITCODE"
        }
        Write-Host "[+] Build OK -> $exe"
    } finally {
        Pop-Location
    }
}

# --- Build CLI args ---
$argList = @("--port", $Port, "--ae-title", $AeTitle)

if ($Tls) {
    if (-not $TlsPfx) { $TlsPfx = $defaultPfx }
    if (-not (Test-Path $TlsPfx)) {
        if ($TlsPfx -ne $defaultPfx) {
            throw "TLS pfx not found: $TlsPfx"
        }
        Write-Host "[i] No fodicom-harness.pfx -- generating one."
        & (Join-Path $here "gen-cert.ps1")
        if (-not (Test-Path $defaultPfx)) {
            throw "gen-cert.ps1 did not produce $defaultPfx"
        }
    }
    $argList += "--tls", $TlsPfx, $TlsPassword
    Write-Host "[+] Starting harness on port $Port (TLS, AE=$AeTitle)"
} else {
    Write-Host "[+] Starting harness on port $Port (plain DIMSE, AE=$AeTitle)"
}

& $exe @argList
