"""Vendored third-party assets bundled with dicom-fuzzer.

Subpackages here ship pre-fetched binaries / configuration that the
fuzzer needs at runtime but doesn't want to require the user to
download separately. Currently:

- ``clrmd/``: Microsoft.Diagnostics.Runtime.dll + a net8.0
  runtimeconfig.json for managed-stack symbolication via pythonnet.
"""
