"""Smoke tests for the bundled fo-dicom file harness.

The harness is a ~50-line .NET 8 console app under
``examples/fodicom-file-harness/`` that ``dicom-fuzzer -t`` invokes
once per fuzzed input. Its exit codes (documented in
``examples/fodicom-file-harness/Program.cs``) drive triage:

* ``0``  -- parsed and traversed cleanly
* ``1``  -- untyped exception during parse (candidate library bug)
* ``2``  -- invalid CLI args
* ``10`` -- :class:`DicomFileException` during parse (designed
  malformation report)
* ``11`` -- untyped exception during pixel decode (candidate codec bug)
* ``12`` -- typed :class:`DicomException` other than
  :class:`DicomFileException`

Previously CI did not run the harness at all, so a refactor that
silently swapped two of these exit codes would only surface in the
next live campaign as a circuit-breaker trip (see #357's commit
message for what that looks like). These tests pin a small subset of
the contract so a future regression in the typed/untyped split fails
CI immediately.

Skipped unless ``DICOM_FUZZER_TEST_FODICOM_HARNESS=1`` is set and
``dotnet`` is on PATH, because building the harness pulls fo-dicom
NuGet packages (~30s first run) -- an unexpected cost for any dev
running ``pytest`` locally without opt-in.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS_DIR = REPO_ROOT / "examples" / "fodicom-file-harness"

_OPT_IN = os.environ.get("DICOM_FUZZER_TEST_FODICOM_HARNESS") == "1"
_HAS_DOTNET = shutil.which("dotnet") is not None

pytestmark = pytest.mark.skipif(
    not (_OPT_IN and _HAS_DOTNET),
    reason=(
        "fo-dicom harness smoke tests are opt-in: set "
        "DICOM_FUZZER_TEST_FODICOM_HARNESS=1 and install the .NET 8 SDK"
    ),
)


@pytest.fixture(scope="module")
def harness_bin(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the harness once per test module and return the binary path."""
    out = tmp_path_factory.mktemp("harness-publish")
    result = subprocess.run(
        [
            "dotnet",
            "publish",
            str(HARNESS_DIR / "fodicom-file-harness.csproj"),
            "-c",
            "Release",
            "-o",
            str(out),
            "--nologo",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(
            f"dotnet publish failed (rc={result.returncode}):\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )

    for name in ("fodicom-file-harness.exe", "fodicom-file-harness"):
        candidate = out / name
        if candidate.exists():
            return candidate

    pytest.fail(
        f"Harness binary not found in {out} after dotnet publish; "
        f"contents: {sorted(p.name for p in out.iterdir())}"
    )


def _run_harness(harness: Path, fixture: Path | None) -> int:
    args = [str(harness)] if fixture is None else [str(harness), str(fixture)]
    return subprocess.run(args, capture_output=True).returncode


def test_no_args_returns_invalid_cli_args(harness_bin: Path) -> None:
    """No path argument -> rc=2 (Program.cs guard at the top of Main)."""
    assert _run_harness(harness_bin, None) == 2


def test_garbage_input_returns_dicomfile_exception(
    harness_bin: Path, tmp_path: Path
) -> None:
    """Bytes that are not a DICOM file -> rc=10 (DicomFileException).

    fo-dicom's ``DicomFile.Open`` rejects input that lacks the
    128-byte preamble + ``DICM`` marker (and any valid file-meta info)
    with :class:`DicomFileException`. This is the harness's "the
    library cleanly rejected your input as designed" code path; the
    1/11 untyped codes are reserved for escapes from the typed
    hierarchy.
    """
    fixture = tmp_path / "garbage.dcm"
    fixture.write_bytes(b"NOT A DICOM FILE" * 64)
    assert _run_harness(harness_bin, fixture) == 10


def test_clean_dicom_returns_zero(harness_bin: Path, tmp_path: Path) -> None:
    """A minimal valid DICOM -> rc=0 (Program.cs happy path).

    Builds a tiny Secondary Capture with explicit-VR little-endian
    file meta and 2x2 8-bit MONOCHROME2 pixel data using pydicom (a
    test dep), so we do not have to commit a binary fixture.
    """
    pydicom = pytest.importorskip("pydicom")
    from pydicom.dataset import FileDataset, FileMetaDataset

    fixture = tmp_path / "clean.dcm"

    sop_class_uid = "1.2.840.10008.5.1.4.1.1.7"  # Secondary Capture
    sop_instance_uid = "1.2.3.4.5.1"

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = sop_class_uid
    file_meta.MediaStorageSOPInstanceUID = sop_instance_uid
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"  # Explicit VR LE
    file_meta.ImplementationClassUID = "1.2.3.4.5"

    ds = FileDataset(
        str(fixture),
        {},
        file_meta=file_meta,
        preamble=b"\x00" * 128,
    )

    ds.SOPClassUID = sop_class_uid
    ds.SOPInstanceUID = sop_instance_uid
    ds.StudyInstanceUID = "1.2.3.4.5.2"
    ds.SeriesInstanceUID = "1.2.3.4.5.3"
    ds.Modality = "OT"
    ds.PatientName = "Test^Patient"
    ds.PatientID = "0001"
    ds.Rows = 2
    ds.Columns = 2
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelRepresentation = 0
    ds.PixelData = b"\x80\x80\x80\x80"

    # pydicom 3.x replaced write_like_original with enforce_file_format
    ds.save_as(fixture, enforce_file_format=True)
    assert pydicom.dcmread(str(fixture)).PixelData == b"\x80\x80\x80\x80"

    assert _run_harness(harness_bin, fixture) == 0
