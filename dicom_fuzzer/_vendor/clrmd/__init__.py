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

CLRMD_VERSION: str = "3.1.512801"
# SHA256 of Microsoft.Diagnostics.Runtime.dll inside the NuGet package
# at CLRMD_VERSION (netstandard2.0 flavour). Pinned so any re-fetch
# (via `dicom-fuzzer install-stack-trace --force`) detects tamper.
#
# Why 3.1 not 4.0: ClrMD 4.x added Azure.Identity / Azure.Core as
# eager dependencies (for symbol-server downloads) which we have no
# practical way to bundle without pulling 10+ transitive DLLs. 3.1
# only needs NETCore.Client + System.Collections.Immutable +
# System.Runtime.CompilerServices.Unsafe, and CoreCLR resolves those
# from the host .NET 8 runtime. 3.1 still handles .NET 8 minidumps
# correctly (the minidump format + ECMA-335 metadata are unchanged
# across runtimes).
CLRMD_SHA256: str | None = (
    "a490408ed34ff08be796812d247680a096336b2b8fdbe5ecdf9f58a9a33473b5"
)
