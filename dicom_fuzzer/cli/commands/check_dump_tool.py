"""``dicom-fuzzer check-dump-tool`` -- Phase 4 pre-flight validator.

Runs the same code path a campaign would when ``--dump-tool`` is set,
but exits before launching anything. Designed to be run once after
``tools/dump-analyzer/build.ps1`` so a misconfigured environment
(wrong path, wrong arch, missing dotnet runtime for fallback) fails
in 2 seconds instead of 8 hours into an overnight Hermes run.

Validations performed, in order:

1. **ProcDump path** -- exists and is a file. (We don't try to
   actually run procdump.exe -- on first run it pops an EULA dialog
   even with -accepteula until the EULA is acked once interactively
   in a separate window; not worth automating around.)
2. **dump-analyzer binary** -- the C# helper published by
   ``tools/dump-analyzer/build.ps1``. Found? -> smoke-test by feeding
   it a non-dump path and verifying it emits the expected JSON-with-
   error-field document (proves the binary launches, finds its
   bundled runtime, and the JSON contract is intact).
3. **dotnet-dump fallback** -- only if (2) is unavailable. We don't
   smoke-test dotnet-dump because the SOS shell-out is slow to spin
   up; just confirm it's on PATH.

Returns 0 when at least ProcDump is configured AND at least one
stack-trace backend is reachable; 1 otherwise. Prints a status table
either way -- useful regardless of exit code.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from dicom_fuzzer.cli.utils import output as cli
from dicom_fuzzer.core.crash.dump_analyzer import _DEFAULT_HELPER


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dicom-fuzzer check-dump-tool",
        description=(
            "Validate ProcDump + ClrMD analyzer setup before running a campaign "
            "with --dump-tool. Detects misconfiguration in seconds rather than "
            "mid-run."
        ),
    )
    p.add_argument(
        "--dump-tool",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Path to procdump.exe. Falls back to env DICOM_FUZZER_PROCDUMP. "
            "Required for the check to be useful."
        ),
    )
    p.add_argument(
        "--analyzer",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Override the dump-analyzer.exe path. Defaults to the location "
            "tools/dump-analyzer/build.ps1 publishes to."
        ),
    )
    return p


def main(argv: list[str]) -> int:
    """Entry point used by the SUBCOMMANDS dispatcher."""
    args = _build_parser().parse_args(argv)

    cli.section("Dump-tool pre-flight")

    ok_procdump = _check_procdump(args.dump_tool)
    ok_backend = _check_stack_backend(args.analyzer)

    print()  # blank line before verdict
    if ok_procdump and ok_backend:
        cli.success("All checks passed -- safe to run a campaign with --dump-tool set.")
        return 0

    cli.warning(
        "One or more checks failed -- a campaign with --dump-tool will "
        "either fail at launch or fall back to exception-code-only "
        "clustering. See messages above."
    )
    return 1


def _check_procdump(explicit: str | None) -> bool:
    """Verify ProcDump path exists. Returns True on success."""
    resolved = explicit or os.environ.get("DICOM_FUZZER_PROCDUMP")
    if not resolved:
        cli.warning(
            "ProcDump: NOT CONFIGURED -- pass --dump-tool PATH or set "
            "DICOM_FUZZER_PROCDUMP. Download from "
            "https://learn.microsoft.com/en-us/sysinternals/downloads/procdump"
        )
        return False

    path = Path(resolved)
    if not path.exists():
        cli.error(f"ProcDump: NOT FOUND at {path}")
        return False
    if not path.is_file():
        cli.error(f"ProcDump: path is not a file: {path}")
        return False
    cli.success(f"ProcDump:  found at {path}")
    return True


def _check_stack_backend(analyzer_override: str | None) -> bool:
    """Verify either the ClrMD helper or dotnet-dump is available.

    Returns True if at least one backend works. We prefer the helper
    because it gives stable symbolic frames; fall through to
    dotnet-dump otherwise.
    """
    helper = Path(analyzer_override) if analyzer_override else _DEFAULT_HELPER
    if helper.exists():
        return _smoke_test_helper(helper)

    cli.warning(
        f"ClrMD helper: not found at {helper}. "
        "Run tools/dump-analyzer/build.ps1 to build it (~67 MB, one-time)."
    )

    dotnet_dump = shutil.which("dotnet-dump")
    if dotnet_dump:
        cli.success(
            f"dotnet-dump fallback: found at {dotnet_dump} "
            "(lower-fidelity stack signatures, but campaigns will run)"
        )
        return True

    cli.error(
        "No stack-trace backend available. Either run "
        "tools/dump-analyzer/build.ps1 OR "
        "`dotnet tool install -g dotnet-dump`."
    )
    return False


def _smoke_test_helper(helper: Path) -> bool:
    """Invoke the helper with a deliberately-bad input to prove it runs.

    Expected behaviour: exits 0 or 1, prints exactly one JSON document
    with an ``error`` field populated and ``frames`` empty. Anything
    else (crash, missing runtime, garbled output) means the binary
    can't be relied on for a real campaign.
    """
    try:
        proc = subprocess.run(
            [str(helper), "C:/__definitely__not_a_dump.dmp"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        cli.error(
            f"ClrMD helper: TIMED OUT during smoke test ({helper}). "
            "Likely a corrupted publish; rebuild via build.ps1."
        )
        return False
    except OSError as e:
        cli.error(f"ClrMD helper: cannot invoke ({helper}): {e}")
        return False

    stdout = proc.stdout.strip()
    if not stdout:
        cli.error(
            f"ClrMD helper: emitted no stdout (rc={proc.returncode}). "
            f"stderr={proc.stderr.strip()[:300]!r}"
        )
        return False
    try:
        doc = json.loads(stdout)
    except json.JSONDecodeError as e:
        cli.error(f"ClrMD helper: stdout is not JSON: {e}")
        return False
    if not isinstance(doc, dict) or "schema_version" not in doc:
        cli.error("ClrMD helper: JSON missing schema_version field")
        return False
    if doc.get("error") is None:
        cli.warning(
            "ClrMD helper: bad-input smoke test did NOT report an error -- "
            "the binary runs but the contract may have drifted; review "
            "tools/dump-analyzer/Program.cs output."
        )
        return True
    cli.success(
        f"ClrMD helper: smoke test passed (binary at {helper}, "
        f"schema_version={doc.get('schema_version')})"
    )
    return True


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
