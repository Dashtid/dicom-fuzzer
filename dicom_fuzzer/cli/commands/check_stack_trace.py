"""``dicom-fuzzer check-stack-trace`` -- pre-flight validator.

Runs the three checks a campaign with ``--dump-dir`` needs:

1. **pythonnet** importable -- shipped as a base dependency so this
   should always pass on Windows after ``uv tool install dicom-fuzzer``.
2. **ClrMD DLL** vendored -- committed under
   ``dicom_fuzzer/_vendor/clrmd/``, so this should pass on any clone
   or wheel. We don't actually *load* the DLL here because that
   requires a live .NET runtime; we just verify the file is present
   and non-trivial size.
3. **createdump.exe** discoverable -- a .NET 5+ runtime is installed
   so the hang-dump path works. Hermes is .NET 8 so the user already
   has this; the check is here to catch host misconfigurations.

Exit code 0 if all three pass, 1 otherwise. Prints a status table
either way. Designed to fail in seconds rather than 8 hours into
an overnight Hermes run.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dicom_fuzzer.cli.utils import output as cli
from dicom_fuzzer.core.crash.createdump import find_createdump
from dicom_fuzzer.core.crash.dump_analyzer import _CLRMD_DLL


def _build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="dicom-fuzzer check-stack-trace",
        description=(
            "Validate the stack-trace toolchain before running a campaign "
            "with --dump-dir set. Detects misconfiguration in seconds "
            "rather than mid-run."
        ),
    )


def main(argv: list[str]) -> int:
    """Subcommand entry point."""
    _build_parser().parse_args(argv)

    cli.section("Stack-trace pre-flight")

    ok_pythonnet = _check_pythonnet()
    ok_dll = _check_clrmd_dll()
    ok_createdump = _check_createdump()

    print()
    if ok_pythonnet and ok_dll and ok_createdump:
        cli.success("All checks passed -- safe to run a campaign with --dump-dir set.")
        return 0

    cli.warning(
        "One or more checks failed -- a campaign with --dump-dir will fall "
        "back to exception-code-only clustering or skip dumps entirely. "
        "See messages above."
    )
    return 1


def _check_pythonnet() -> bool:
    """Confirm pythonnet is installed (we don't actually call it)."""
    try:
        import pythonnet  # noqa: F401
    except ImportError:
        cli.error(
            "pythonnet: NOT INSTALLED. This is unexpected -- pythonnet is "
            "a base dependency. Re-run `uv tool install dicom-fuzzer` "
            "(or `pip install pythonnet>=3.0`) and try again."
        )
        return False
    cli.success("pythonnet: installed")
    return True


def _check_clrmd_dll() -> bool:
    """Verify the vendored DLL exists and looks like a real PE file."""
    dll = Path(_CLRMD_DLL)
    if not dll.exists():
        cli.error(
            f"ClrMD DLL: NOT FOUND at {dll}. This is unexpected -- the "
            "DLL is committed to the repo. Re-clone the repo or re-run "
            "`uv tool install dicom-fuzzer`."
        )
        return False
    size = dll.stat().st_size
    if size < 100_000:
        cli.error(
            f"ClrMD DLL: at {dll} but suspiciously small ({size} bytes). "
            "Re-run `dicom-fuzzer install-stack-trace --force`."
        )
        return False
    # Quick PE-magic check: real DLLs start with 'MZ'
    with dll.open("rb") as f:
        magic = f.read(2)
    if magic != b"MZ":
        cli.error(
            f"ClrMD DLL: at {dll} but not a PE file (magic={magic!r}). "
            "Re-run `dicom-fuzzer install-stack-trace --force`."
        )
        return False
    cli.success(f"ClrMD DLL: {dll} ({size:,} bytes)")
    return True


def _check_createdump() -> bool:
    """Confirm a .NET runtime ships createdump.exe somewhere reachable."""
    exe = find_createdump()
    if exe is None:
        cli.warning(
            "createdump.exe: NOT FOUND -- hang dumps will be skipped. "
            "Install the .NET 8 desktop runtime to enable."
        )
        return False
    cli.success(f"createdump.exe: {exe}")
    return True


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
