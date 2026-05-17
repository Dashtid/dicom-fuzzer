"""ClrMD + runtimeconfig vendored for managed stack symbolication.

We ship Microsoft.Diagnostics.Runtime.dll directly in the wheel
(~2MB, MIT-licensed) so users don't need to ``dotnet tool install``
anything. Pinned version is recorded in ``CLRMD_VERSION`` for
reproducibility / refresh tooling.

On a fresh dev clone the DLL is not present (Git LFS would be
overkill for one file). Either:

1. Run ``python -m dicom_fuzzer.cli.commands.install_stack_trace``
   which fetches it from NuGet, verifies SHA256, and drops it here.
2. Or ``uv tool install dicom-fuzzer`` from a published wheel,
   which already bundles the DLL.
"""

CLRMD_VERSION: str = "4.0.726401"
# SHA256 of Microsoft.Diagnostics.Runtime.dll inside the NuGet package at
# CLRMD_VERSION. Populated by install_stack_trace on first fetch; pin
# here once verified so subsequent fetches detect tamper.
CLRMD_SHA256: str | None = None
