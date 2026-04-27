"""Tests for the DICOM-aware crash minimizer."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pydicom
import pytest
from pydicom.dataset import FileDataset, FileMetaDataset

from dicom_fuzzer.core.crash.minimizer import (
    MinimizationError,
    ddmin,
    minimize_dicom,
)

# ---------------------------------------------------------------------------
# ddmin algorithmic tests (pure, no I/O)
# ---------------------------------------------------------------------------


class TestDdmin:
    def test_returns_input_when_single_item(self):
        result = ddmin([1], lambda s: True)
        assert result == [1]

    def test_returns_empty_when_empty(self):
        result = ddmin([], lambda s: True)
        assert result == []

    def test_reduces_to_single_required_item(self):
        """Predicate is true iff item 5 is in the subset."""
        items = [1, 2, 3, 4, 5, 6, 7, 8]
        result = ddmin(items, lambda s: 5 in s)
        assert result == [5]

    def test_keeps_all_when_all_required(self):
        """Predicate needs the full set."""
        items = [1, 2, 3, 4]
        result = ddmin(items, lambda s: len(s) == 4)
        assert result == items

    def test_preserves_order(self):
        """The reduced subset keeps items in original order."""
        items = ["a", "b", "c", "d", "e"]

        # Predicate: true if 'b' appears before 'd' in the subset
        def pred(s):
            try:
                return s.index("b") < s.index("d")
            except ValueError:
                return False

        result = ddmin(items, pred)
        assert "b" in result
        assert "d" in result
        assert result.index("b") < result.index("d")

    def test_handles_two_required_items(self):
        """Predicate needs both 3 and 7."""
        items = list(range(10))
        result = ddmin(items, lambda s: 3 in s and 7 in s)
        assert sorted(result) == [3, 7]

    def test_does_not_call_predicate_with_empty_when_redundant(self):
        """ddmin should not get stuck calling predicate on empty list."""
        calls = []

        def pred(s):
            calls.append(list(s))
            return 1 in s

        ddmin([1, 2, 3], pred)
        # Empty subset should not be a query (would trivially fail)
        assert all(len(c) > 0 for c in calls)


# ---------------------------------------------------------------------------
# minimize_dicom integration tests with a fake Python target
# ---------------------------------------------------------------------------


def _make_fake_target(tmp_path: Path, required_tag_hex: str, expected_rc: int) -> Path:
    """Write a Python script that exits with *expected_rc* iff the input file
    has a DataElement at *required_tag_hex* (e.g. '00100010'). Otherwise exits 0.

    Returns the path to the script. Caller invokes via [sys.executable, script].
    """
    script_path = tmp_path / "fake_target.py"
    script_path.write_text(
        textwrap.dedent(f"""\
            import sys
            import pydicom

            try:
                ds = pydicom.dcmread(sys.argv[1], force=True)
            except Exception:
                sys.exit(99)

            tag = pydicom.tag.Tag(0x{required_tag_hex})
            if tag in ds:
                sys.exit({expected_rc})
            sys.exit(0)
        """)
    )
    return script_path


def _make_fake_target_wrapper(tmp_path: Path, script_path: Path) -> Path:
    """Wrap the python script in a .bat (Windows) or .sh (POSIX) so we can
    pass a single 'executable' to subprocess.run."""
    if sys.platform == "win32":
        wrapper = tmp_path / "target.bat"
        wrapper.write_text(f'@"{sys.executable}" "{script_path}" %1\n')
    else:
        wrapper = tmp_path / "target.sh"
        wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script_path}" "$1"\n')
        wrapper.chmod(0o755)
    return wrapper


def _make_dicom_file(
    tmp_path: Path,
    name: str = "input.dcm",
    extra_tags: list[tuple[int, str, object]] | None = None,
) -> Path:
    """Build a small but valid DICOM file with at least the SOP class element."""
    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.7"
    file_meta.MediaStorageSOPInstanceUID = "1.2.3.4.5"
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"
    file_meta.ImplementationClassUID = "1.2.3.4"

    ds = FileDataset(
        str(tmp_path / name), {}, file_meta=file_meta, preamble=b"\0" * 128
    )
    ds.PatientName = "TEST^PATIENT"
    ds.PatientID = "12345"
    ds.StudyDate = "20260101"
    ds.Modality = "OT"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.7"
    ds.SOPInstanceUID = "1.2.3.4.5"

    if extra_tags:
        for tag, vr, value in extra_tags:
            ds.add_new(tag, vr, value)

    out = tmp_path / name
    ds.save_as(str(out), write_like_original=False)
    return out


class TestMinimizeDicom:
    def test_raises_when_input_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            minimize_dicom(
                crashing_path=tmp_path / "nope.dcm",
                target_exe=tmp_path / "also-nope",
                expected_returncode=1,
            )

    def test_raises_when_target_missing(self, tmp_path):
        crashing = _make_dicom_file(tmp_path)
        with pytest.raises(FileNotFoundError):
            minimize_dicom(
                crashing_path=crashing,
                target_exe=tmp_path / "missing-target",
                expected_returncode=1,
            )

    def test_raises_when_original_does_not_crash(self, tmp_path):
        """Original file lacks the required tag → predicate fails on full input."""
        crashing = _make_dicom_file(tmp_path)
        # Target requires (0008,0070) Manufacturer, which our file does NOT have.
        script = _make_fake_target(tmp_path, "00080070", expected_rc=1)
        target = _make_fake_target_wrapper(tmp_path, script)
        with pytest.raises(MinimizationError, match="does not reproduce"):
            minimize_dicom(
                crashing_path=crashing,
                target_exe=target,
                expected_returncode=1,
                timeout=10.0,
            )

    def test_reduces_to_required_element(self, tmp_path):
        """File has 6 elements; only PatientName triggers the 'crash'."""
        crashing = _make_dicom_file(tmp_path)
        script = _make_fake_target(tmp_path, "00100010", expected_rc=42)
        target = _make_fake_target_wrapper(tmp_path, script)

        result = minimize_dicom(
            crashing_path=crashing,
            target_exe=target,
            expected_returncode=42,
            timeout=10.0,
            output_path=tmp_path / "minimized.dcm",
        )

        assert result.minimized_element_count >= 1
        assert result.minimized_element_count < result.original_element_count

        # Verify the minimized file actually contains PatientName
        out = pydicom.dcmread(str(tmp_path / "minimized.dcm"), force=True)
        assert pydicom.tag.Tag(0x00100010) in out

    def test_writes_output_to_default_path_when_unspecified(self, tmp_path):
        crashing = _make_dicom_file(tmp_path)
        script = _make_fake_target(tmp_path, "00100010", expected_rc=42)
        target = _make_fake_target_wrapper(tmp_path, script)

        result = minimize_dicom(
            crashing_path=crashing,
            target_exe=target,
            expected_returncode=42,
        )

        expected_output = crashing.with_suffix(".minimized.dcm")
        assert expected_output.exists()
        assert result.minimized_byte_size == expected_output.stat().st_size

    def test_respects_max_trials(self, tmp_path):
        """max_trials=1 means only the sanity check runs, no real reduction."""
        crashing = _make_dicom_file(tmp_path)
        script = _make_fake_target(tmp_path, "00100010", expected_rc=42)
        target = _make_fake_target_wrapper(tmp_path, script)

        result = minimize_dicom(
            crashing_path=crashing,
            target_exe=target,
            expected_returncode=42,
            max_trials=1,
            output_path=tmp_path / "minimized.dcm",
        )
        # First trial = sanity check; predicate calls all return None (budget out)
        # so ddmin's predicates fail → no reduction happens.
        assert result.trial_count == 1
        assert result.minimized_element_count == result.original_element_count

    def test_reports_kept_and_removed_lists(self, tmp_path):
        crashing = _make_dicom_file(tmp_path)
        script = _make_fake_target(tmp_path, "00100010", expected_rc=42)
        target = _make_fake_target_wrapper(tmp_path, script)

        result = minimize_dicom(
            crashing_path=crashing,
            target_exe=target,
            expected_returncode=42,
            output_path=tmp_path / "minimized.dcm",
        )

        assert isinstance(result.elements_kept, list)
        assert isinstance(result.elements_removed, list)
        assert (
            len(result.elements_kept) + len(result.elements_removed)
            == result.original_element_count
        )
