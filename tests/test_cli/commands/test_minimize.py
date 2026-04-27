"""Tests for the minimize CLI subcommand."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pydicom
from pydicom.dataset import FileDataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.cli.commands.minimize import create_parser, main


def _make_dicom(path: Path) -> Path:
    fm = FileMetaDataset()
    fm.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.7"
    fm.MediaStorageSOPInstanceUID = generate_uid()
    fm.TransferSyntaxUID = ExplicitVRLittleEndian
    fm.ImplementationClassUID = generate_uid()
    ds = FileDataset(str(path), {}, file_meta=fm, preamble=b"\0" * 128)
    ds.PatientName = "TEST"
    ds.PatientID = "1"
    ds.SOPClassUID = fm.MediaStorageSOPClassUID
    ds.SOPInstanceUID = fm.MediaStorageSOPInstanceUID
    ds.Modality = "OT"
    ds.save_as(str(path), write_like_original=False)
    return path


def _make_target(tmp_path: Path, expect_tag_hex: str, exit_code: int) -> Path:
    """Build a Python-script-backed wrapper that exits *exit_code* iff the input
    contains the given tag, else 0."""
    script = tmp_path / "fake_target.py"
    script.write_text(
        textwrap.dedent(f"""\
            import sys
            import pydicom
            try:
                ds = pydicom.dcmread(sys.argv[1], force=True)
            except Exception:
                sys.exit(99)
            if pydicom.tag.Tag(0x{expect_tag_hex}) in ds:
                sys.exit({exit_code})
            sys.exit(0)
        """)
    )
    if sys.platform == "win32":
        wrapper = tmp_path / "target.bat"
        wrapper.write_text(f'@"{sys.executable}" "{script}" %1\n')
    else:
        wrapper = tmp_path / "target.sh"
        wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$1"\n')
        wrapper.chmod(0o755)
    return wrapper


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


class TestParser:
    def test_required_args(self):
        parser = create_parser()
        args = parser.parse_args(["in.dcm", "-t", "tgt.exe", "--expect-rc", "1"])
        assert args.input == Path("in.dcm")
        assert args.target == Path("tgt.exe")
        assert args.expected_rc == 1
        assert args.timeout == 10.0
        assert args.max_trials == 500
        assert args.output is None

    def test_custom_flags(self):
        parser = create_parser()
        args = parser.parse_args(
            [
                "in.dcm",
                "-t",
                "tgt.exe",
                "--expect-rc",
                "139",
                "--timeout",
                "5",
                "--max-trials",
                "200",
                "-o",
                "out.dcm",
                "-v",
            ]
        )
        assert args.expected_rc == 139
        assert args.timeout == 5.0
        assert args.max_trials == 200
        assert args.output == Path("out.dcm")
        assert args.verbose is True


# ---------------------------------------------------------------------------
# main() integration tests
# ---------------------------------------------------------------------------


class TestMain:
    def test_missing_input_returns_1(self, tmp_path, capsys):
        target = _make_target(tmp_path, "00100010", 42)
        rc = main(
            [
                str(tmp_path / "nope.dcm"),
                "-t",
                str(target),
                "--expect-rc",
                "42",
            ]
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "Input file not found" in err

    def test_missing_target_returns_1(self, tmp_path, capsys):
        input_dcm = _make_dicom(tmp_path / "in.dcm")
        rc = main(
            [
                str(input_dcm),
                "-t",
                str(tmp_path / "no-target.exe"),
                "--expect-rc",
                "42",
            ]
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "Target executable not found" in err

    def test_original_does_not_crash_returns_2(self, tmp_path, capsys):
        """Target wants tag (0008,0070) which our fixture doesn't have."""
        input_dcm = _make_dicom(tmp_path / "in.dcm")
        target = _make_target(tmp_path, "00080070", 42)
        rc = main(
            [
                str(input_dcm),
                "-t",
                str(target),
                "--expect-rc",
                "42",
                "--max-trials",
                "10",
            ]
        )
        assert rc == 2

    def test_successful_minimization(self, tmp_path, capsys):
        input_dcm = _make_dicom(tmp_path / "in.dcm")
        target = _make_target(tmp_path, "00100010", 42)
        out = tmp_path / "min.dcm"
        rc = main(
            [
                str(input_dcm),
                "-t",
                str(target),
                "--expect-rc",
                "42",
                "-o",
                str(out),
            ]
        )
        assert rc == 0
        assert out.exists()
        captured = capsys.readouterr()
        assert "Minimized:" in captured.out
        assert "Elements:" in captured.out
        # Minimized file must still trigger the crash
        ds = pydicom.dcmread(str(out), force=True)
        assert pydicom.tag.Tag(0x00100010) in ds
