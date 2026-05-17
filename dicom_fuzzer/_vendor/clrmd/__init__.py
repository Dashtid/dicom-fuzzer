"""ClrMD + runtimeconfig vendored for managed stack symbolication.

We ship Microsoft.Diagnostics.Runtime.dll directly in the wheel
(~2MB, MIT-licensed) so users don't need to ``dotnet tool install``
anything. Pinned version is recorded in ``CLRMD_VERSION`` for
reproducibility / refresh tooling.

The DLL is committed to the repo (~770 KB), so it ships with every
clone and every wheel. Run ``dicom-fuzzer install-stack-trace
--force`` to bump to a newer ClrMD release; commit the resulting
DLL + updated SHA256 pin in this file.
"""

CLRMD_VERSION: str = "4.0.726401"
# SHA256 of Microsoft.Diagnostics.Runtime.dll inside the NuGet package
# at CLRMD_VERSION (netstandard2.0 flavour). Pinned so any re-fetch
# (via `dicom-fuzzer install-stack-trace --force`) detects tamper.
CLRMD_SHA256: str | None = (
    "42fbe6fd099163063294b28a0a50f9393cc5d5f6e0f0e09c28dfbd96f7a9852a"
)
