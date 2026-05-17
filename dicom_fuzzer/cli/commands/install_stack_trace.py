"""dicom-fuzzer install-stack-trace -- one-time DLL fetcher.

Downloads ``Microsoft.Diagnostics.Runtime`` from NuGet, extracts the
DLL into ``dicom_fuzzer/_vendor/clrmd/``, and verifies SHA256 against
the pinned value. Idempotent: re-running with the same version is a
no-op when the DLL is already present and its checksum matches.

We do this dynamically rather than committing the binary to git
because (a) the 2 MB binary doesn't fit Git's diff workflow, (b)
shipping the wheel itself bundles the DLL, so end users installing
via ``uv tool install dicom-fuzzer`` never hit this code path — only
fresh developer clones do.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

from dicom_fuzzer._vendor.clrmd import CLRMD_SHA256, CLRMD_VERSION
from dicom_fuzzer.cli.utils import output as cli

_NUPKG_URL = (
    "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Runtime/{version}"
)
_DLL_PATH_IN_NUPKG = "lib/net6.0/Microsoft.Diagnostics.Runtime.dll"
_TARGET_DLL = (
    Path(__file__).parent.parent.parent
    / "_vendor"
    / "clrmd"
    / "Microsoft.Diagnostics.Runtime.dll"
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dicom-fuzzer install-stack-trace",
        description=(
            "Fetch the ClrMD DLL needed for symbolic stack-trace "
            "extraction. Run once after cloning the repo. End users "
            "installing from a published wheel never need this."
        ),
    )
    p.add_argument(
        "--version",
        default=CLRMD_VERSION,
        help=f"NuGet version to fetch (default: {CLRMD_VERSION}).",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if the DLL is already present and valid.",
    )
    return p


def main(argv: list[str]) -> int:
    """Subcommand entry point."""
    args = _build_parser().parse_args(argv)

    cli.section("ClrMD DLL installer")

    if _TARGET_DLL.exists() and not args.force:
        actual = _sha256_of(_TARGET_DLL)
        if CLRMD_SHA256 is None:
            cli.success(
                f"ClrMD DLL already at {_TARGET_DLL} ({_TARGET_DLL.stat().st_size:,} bytes). "
                f"SHA256={actual} (no pinned hash to compare against)."
            )
            return 0
        if actual == CLRMD_SHA256:
            cli.success(f"ClrMD DLL already at {_TARGET_DLL}; checksum OK.")
            return 0
        cli.warning(
            f"Existing DLL hash mismatch (expected {CLRMD_SHA256}, got {actual}). "
            "Re-fetching."
        )

    url = _NUPKG_URL.format(version=args.version)
    cli.info(f"Downloading {url} ...")
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310  # nosec B310 -- pinned NuGet URL
            nupkg_bytes = resp.read()
    except Exception as exc:
        cli.error(f"NuGet download failed: {exc}")
        return 1

    cli.info(f"Got {len(nupkg_bytes):,} bytes; extracting {_DLL_PATH_IN_NUPKG} ...")
    try:
        with zipfile.ZipFile(io.BytesIO(nupkg_bytes)) as zf:
            dll_bytes = zf.read(_DLL_PATH_IN_NUPKG)
    except (KeyError, zipfile.BadZipFile) as exc:
        cli.error(
            f"Could not extract {_DLL_PATH_IN_NUPKG} from nupkg: {exc}. "
            "Has the NuGet layout changed?"
        )
        return 1

    actual = hashlib.sha256(dll_bytes).hexdigest()
    if CLRMD_SHA256 is not None and actual != CLRMD_SHA256:
        cli.error(
            f"DLL checksum mismatch: expected {CLRMD_SHA256}, got {actual}. "
            "Refusing to install. Investigate before bumping the pin."
        )
        return 1

    _TARGET_DLL.parent.mkdir(parents=True, exist_ok=True)
    _TARGET_DLL.write_bytes(dll_bytes)
    cli.success(f"Installed {_TARGET_DLL} ({len(dll_bytes):,} bytes, sha256={actual}).")
    if CLRMD_SHA256 is None:
        cli.info(
            "Tip: pin CLRMD_SHA256 in dicom_fuzzer/_vendor/clrmd/__init__.py "
            f"to '{actual}' to enable tamper detection on future runs."
        )
    return 0


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
