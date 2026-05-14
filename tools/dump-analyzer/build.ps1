# Build script for the ClrMD-based dump analyzer.
#
# Produces a self-contained single-file Windows x64 executable that the
# Python wrapper (dicom_fuzzer.core.crash.dump_analyzer) invokes per
# captured minidump. Run once per environment; the Python wrapper looks
# for the binary at bin/Release/net8.0/win-x64/publish/dump-analyzer.exe.
#
# The output is ~67 MB self-contained -- intentionally NOT checked into
# the repo. Re-run after pulling changes to tools/dump-analyzer/.

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here
try {
    dotnet publish -c Release
    $exe = Join-Path $here "bin/Release/net8.0/win-x64/publish/dump-analyzer.exe"
    if (-not (Test-Path $exe)) {
        Write-Error "Publish succeeded but expected output is missing: $exe"
        exit 1
    }
    Write-Host "[+] Built: $exe ($([math]::Round((Get-Item $exe).Length / 1MB, 1)) MB)"
} finally {
    Pop-Location
}
