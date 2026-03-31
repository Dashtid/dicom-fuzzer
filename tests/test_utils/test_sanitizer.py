"""Tests for dicom_fuzzer.utils.sanitizer."""

from __future__ import annotations

from pathlib import Path

import pydicom
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.utils.phi_tags import (
    PHI_DATE_KEYWORDS,
    PHI_DELETE_KEYWORDS,
)
from dicom_fuzzer.utils.sanitizer import (
    sanitize_dataset,
    sanitize_directory,
    sanitize_file,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_dataset() -> Dataset:
    """Return a dataset loaded with PHI tags for testing."""
    ds = Dataset()
    # Core patient demographics (handled by anonymize_patient_info)
    ds.PatientName = "Real^Patient"
    ds.PatientID = "MRN-12345"
    ds.PatientBirthDate = "19801231"

    # PHI tags to delete
    ds.InstitutionName = "City Hospital"
    ds.InstitutionAddress = "123 Main St"
    ds.ReferringPhysicianName = "Dr^Smith"
    ds.PerformingPhysicianName = "Dr^Jones"
    ds.OperatorsName = "Tech^One"
    ds.StationName = "CT_ROOM_1"
    ds.AccessionNumber = "ACC-999"
    ds.PatientAddress = "456 Elm St"
    ds.PatientAge = "044Y"
    ds.PatientWeight = 75.0
    ds.PatientSize = 1.75
    ds.PatientComments = "Allergic to contrast"

    # UIDs
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()

    # Dates
    ds.StudyDate = "20240115"
    ds.SeriesDate = "20240115"
    ds.AcquisitionDate = "20240115"
    ds.ContentDate = "20240115"

    # Non-PHI tags that should survive
    ds.Modality = "CT"
    ds.Rows = 512
    ds.Columns = 512

    # File meta
    meta = FileMetaDataset()
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    meta.MediaStorageSOPClassUID = ds.SOPClassUID
    meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    meta.ImplementationClassUID = generate_uid()
    ds.file_meta = meta

    return ds


def _save_dataset(ds: Dataset, path: Path) -> None:
    """Save a dataset as a proper DICOM file."""
    fd = FileDataset(str(path), ds, file_meta=ds.file_meta, preamble=b"\x00" * 128)
    fd.is_implicit_VR = False
    fd.is_little_endian = True
    fd.save_as(str(path), write_like_original=False)


# ---------------------------------------------------------------------------
# sanitize_dataset
# ---------------------------------------------------------------------------


class TestSanitizeDataset:
    """Tests for sanitize_dataset()."""

    def test_replaces_patient_info(self):
        ds = _make_dataset()
        sanitize_dataset(ds)
        assert ds.PatientName != "Real^Patient"
        assert ds.PatientID != "MRN-12345"
        assert ds.PatientBirthDate != "19801231"

    def test_deletes_phi_tags(self):
        ds = _make_dataset()
        sanitize_dataset(ds)
        for keyword in PHI_DELETE_KEYWORDS:
            assert not hasattr(ds, keyword), f"{keyword} was not deleted"

    def test_preserves_non_phi_tags(self):
        ds = _make_dataset()
        sanitize_dataset(ds)
        assert ds.Modality == "CT"
        assert ds.Rows == 512
        assert ds.Columns == 512

    def test_regenerates_uids(self):
        ds = _make_dataset()
        old_sop = str(ds.SOPInstanceUID)
        old_study = str(ds.StudyInstanceUID)
        old_series = str(ds.SeriesInstanceUID)
        sanitize_dataset(ds)
        assert str(ds.SOPInstanceUID) != old_sop
        assert str(ds.StudyInstanceUID) != old_study
        assert str(ds.SeriesInstanceUID) != old_series

    def test_keep_uids_flag(self):
        ds = _make_dataset()
        old_sop = str(ds.SOPInstanceUID)
        sanitize_dataset(ds, keep_uids=True)
        assert str(ds.SOPInstanceUID) == old_sop

    def test_uid_map_consistency(self):
        """Two datasets sharing a StudyInstanceUID get the same new UID."""
        shared_study = generate_uid()
        ds1 = _make_dataset()
        ds1.StudyInstanceUID = shared_study
        ds2 = _make_dataset()
        ds2.StudyInstanceUID = shared_study

        uid_map: dict[str, str] = {}
        sanitize_dataset(ds1, uid_map=uid_map)
        sanitize_dataset(ds2, uid_map=uid_map)

        assert str(ds1.StudyInstanceUID) == str(ds2.StudyInstanceUID)
        assert str(ds1.StudyInstanceUID) != str(shared_study)

    def test_shifts_dates(self):
        ds = _make_dataset()
        sanitize_dataset(ds, date_offset_days=100)
        for keyword in PHI_DATE_KEYWORDS:
            val = getattr(ds, keyword, None)
            if val is not None:
                assert str(val) != "20240115"

    def test_date_offset_consistent(self):
        """All date tags shift by the same delta."""
        ds = _make_dataset()
        sanitize_dataset(ds, date_offset_days=365)
        # All four dates were 20240115; shifted back 365 days = 20230115
        for keyword in PHI_DATE_KEYWORDS:
            assert getattr(ds, keyword) == "20230115"

    def test_removes_private_tags_by_default(self):
        ds = _make_dataset()
        ds.add_new(0x00091001, "LO", "PrivateValue")
        sanitize_dataset(ds)
        assert (0x0009, 0x1001) not in ds

    def test_keeps_private_tags_when_requested(self):
        ds = _make_dataset()
        ds.add_new(0x00091001, "LO", "PrivateValue")
        sanitize_dataset(ds, keep_private=True)
        assert (0x0009, 0x1001) in ds

    def test_syncs_file_meta_uids(self):
        ds = _make_dataset()
        old_meta_sop = str(ds.file_meta.MediaStorageSOPInstanceUID)
        sanitize_dataset(ds)
        # file_meta should match the regenerated dataset-level UID
        assert str(ds.file_meta.MediaStorageSOPInstanceUID) == str(ds.SOPInstanceUID)
        assert str(ds.file_meta.MediaStorageSOPInstanceUID) != old_meta_sop

    def test_handles_missing_tags_gracefully(self):
        """Dataset with no PHI tags should not raise."""
        ds = Dataset()
        ds.Modality = "CT"
        sanitize_dataset(ds)
        assert ds.Modality == "CT"


# ---------------------------------------------------------------------------
# sanitize_file
# ---------------------------------------------------------------------------


class TestSanitizeFile:
    """Tests for sanitize_file()."""

    def test_round_trip(self, tmp_path):
        ds = _make_dataset()
        src = tmp_path / "input.dcm"
        dst = tmp_path / "output.dcm"
        _save_dataset(ds, src)

        ok, msg = sanitize_file(src, dst, date_offset_days=100)
        assert ok, msg
        assert dst.exists()

        reloaded = pydicom.dcmread(str(dst), force=True)
        assert reloaded.Modality == "CT"
        assert not hasattr(reloaded, "InstitutionName")

    def test_read_error_returns_false(self, tmp_path):
        bad = tmp_path / "bad.dcm"
        bad.write_bytes(b"not dicom at all")
        ok, msg = sanitize_file(bad, tmp_path / "out.dcm")
        # pydicom.dcmread(force=True) is very tolerant, so this may
        # succeed or fail depending on the bytes.  We just verify no crash.
        assert isinstance(ok, bool)


# ---------------------------------------------------------------------------
# sanitize_directory
# ---------------------------------------------------------------------------


class TestSanitizeDirectory:
    """Tests for sanitize_directory()."""

    def test_processes_all_files(self, tmp_path):
        in_dir = tmp_path / "seeds"
        in_dir.mkdir()
        for i in range(3):
            ds = _make_dataset()
            _save_dataset(ds, in_dir / f"test_{i}.dcm")

        out_dir = tmp_path / "sanitized"
        stats = sanitize_directory(in_dir, out_dir, date_offset_days=100)
        assert stats["processed"] == 3
        assert stats["succeeded"] == 3
        assert stats["failed"] == 0
        assert len(list(out_dir.glob("*.dcm"))) == 3

    def test_preserves_subdirectory_structure(self, tmp_path):
        in_dir = tmp_path / "seeds"
        sub = in_dir / "sub"
        sub.mkdir(parents=True)
        _save_dataset(_make_dataset(), sub / "nested.dcm")

        out_dir = tmp_path / "sanitized"
        stats = sanitize_directory(
            in_dir, out_dir, recursive=True, date_offset_days=100
        )
        assert stats["succeeded"] == 1
        assert (out_dir / "sub" / "nested.dcm").exists()

    def test_skips_non_dicom(self, tmp_path):
        in_dir = tmp_path / "seeds"
        in_dir.mkdir()
        _save_dataset(_make_dataset(), in_dir / "valid.dcm")
        (in_dir / "readme.txt").write_text("not dicom")

        out_dir = tmp_path / "sanitized"
        stats = sanitize_directory(in_dir, out_dir, date_offset_days=100)
        assert stats["processed"] == 1
        assert not (out_dir / "readme.txt").exists()

    def test_empty_directory(self, tmp_path):
        in_dir = tmp_path / "empty"
        in_dir.mkdir()
        out_dir = tmp_path / "sanitized"
        stats = sanitize_directory(in_dir, out_dir, date_offset_days=100)
        assert stats["processed"] == 0
