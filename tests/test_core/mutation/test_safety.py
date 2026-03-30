"""Unit tests for dicom_fuzzer.core.mutation.safety."""

from __future__ import annotations

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.core.mutation.safety import (
    SAFETY_LEVELS,
    VALID_SAFETY_MODES,
    restore_critical_tags,
    snapshot_critical_tags,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_dataset() -> Dataset:
    """Return a dataset with all critical tags populated."""
    ds = Dataset()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.Modality = "CT"
    ds.PatientName = "Test^Patient"

    meta = FileMetaDataset()
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    meta.MediaStorageSOPClassUID = ds.SOPClassUID
    meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    ds.file_meta = meta

    return ds


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestSafetyConstants:
    """Verify module-level constants are consistent."""

    def test_valid_modes_includes_off(self):
        assert "off" in VALID_SAFETY_MODES

    def test_valid_modes_includes_lenient(self):
        assert "lenient" in VALID_SAFETY_MODES

    def test_valid_modes_includes_strict(self):
        assert "strict" in VALID_SAFETY_MODES

    def test_safety_levels_keys(self):
        assert set(SAFETY_LEVELS.keys()) == {"lenient", "strict"}

    def test_lenient_only_tier1(self):
        level = SAFETY_LEVELS["lenient"]
        assert level["file_meta"] == frozenset({"TransferSyntaxUID"})
        assert level["dataset"] == frozenset()

    def test_strict_covers_all_tiers(self):
        level = SAFETY_LEVELS["strict"]
        assert "TransferSyntaxUID" in level["file_meta"]
        assert "MediaStorageSOPClassUID" in level["file_meta"]
        assert "MediaStorageSOPInstanceUID" in level["file_meta"]
        assert "SOPClassUID" in level["dataset"]
        assert "SOPInstanceUID" in level["dataset"]
        assert "StudyInstanceUID" in level["dataset"]
        assert "SeriesInstanceUID" in level["dataset"]


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


class TestSnapshot:
    """Tests for snapshot_critical_tags."""

    def test_captures_existing_tags_strict(self):
        ds = _make_dataset()
        snap = snapshot_critical_tags(ds, "strict")
        assert "ds:SOPClassUID" in snap
        assert "ds:SOPInstanceUID" in snap
        assert "ds:StudyInstanceUID" in snap
        assert "ds:SeriesInstanceUID" in snap
        assert "meta:TransferSyntaxUID" in snap
        assert "meta:MediaStorageSOPClassUID" in snap
        assert "meta:MediaStorageSOPInstanceUID" in snap

    def test_handles_missing_tags(self):
        ds = Dataset()
        ds.Modality = "CT"
        snap = snapshot_critical_tags(ds, "strict")
        # No critical tags exist, so snapshot is empty
        assert snap == {}

    def test_handles_missing_file_meta(self):
        ds = Dataset()
        ds.SOPClassUID = "1.2.3"
        snap = snapshot_critical_tags(ds, "strict")
        assert "ds:SOPClassUID" in snap
        assert not any(k.startswith("meta:") for k in snap)

    def test_lenient_captures_only_transfer_syntax(self):
        ds = _make_dataset()
        snap = snapshot_critical_tags(ds, "lenient")
        assert "meta:TransferSyntaxUID" in snap
        # Lenient should NOT capture dataset-level tags
        assert not any(k.startswith("ds:") for k in snap)
        # Lenient should NOT capture Tier-2 file_meta tags
        assert "meta:MediaStorageSOPClassUID" not in snap

    def test_unknown_mode_returns_empty(self):
        ds = _make_dataset()
        snap = snapshot_critical_tags(ds, "nonexistent")
        assert snap == {}

    def test_snapshot_copies_values(self):
        ds = _make_dataset()
        original_uid = ds.SOPClassUID
        snap = snapshot_critical_tags(ds, "strict")
        # Mutate the dataset
        ds.SOPClassUID = "9.9.9"
        # Snapshot should still have the original
        assert snap["ds:SOPClassUID"] == original_uid


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


class TestRestore:
    """Tests for restore_critical_tags."""

    def test_restores_deleted_tag(self):
        ds = _make_dataset()
        original_uid = ds.SOPClassUID
        snap = snapshot_critical_tags(ds, "strict")
        del ds.SOPClassUID
        restored = restore_critical_tags(ds, snap, "strict")
        assert restored >= 1
        assert ds.SOPClassUID == original_uid

    def test_restores_corrupted_tag(self):
        ds = _make_dataset()
        original_uid = ds.SOPClassUID
        snap = snapshot_critical_tags(ds, "strict")
        ds.SOPClassUID = "CORRUPTED"
        restored = restore_critical_tags(ds, snap, "strict")
        assert restored >= 1
        assert ds.SOPClassUID == original_uid

    def test_preserves_non_critical_mutations(self):
        ds = _make_dataset()
        snap = snapshot_critical_tags(ds, "strict")
        # Mutate non-critical tag
        ds.PatientName = "MUTATED"
        # Delete critical tag
        del ds.SOPClassUID
        restore_critical_tags(ds, snap, "strict")
        # Non-critical mutation should remain
        assert ds.PatientName == "MUTATED"
        # Critical tag should be restored
        assert hasattr(ds, "SOPClassUID")

    def test_restores_file_meta_tag(self):
        ds = _make_dataset()
        original_ts = ds.file_meta.TransferSyntaxUID
        snap = snapshot_critical_tags(ds, "strict")
        ds.file_meta.TransferSyntaxUID = "1.2.3.4.5.6.7"
        restored = restore_critical_tags(ds, snap, "strict")
        assert restored >= 1
        assert ds.file_meta.TransferSyntaxUID == original_ts

    def test_lenient_protects_only_tier1(self):
        ds = _make_dataset()
        original_ts = ds.file_meta.TransferSyntaxUID
        snap = snapshot_critical_tags(ds, "lenient")
        # Corrupt both TransferSyntaxUID and SOPClassUID
        ds.file_meta.TransferSyntaxUID = "1.2.3.4.5.6.7"
        ds.SOPClassUID = "CORRUPTED"
        restored = restore_critical_tags(ds, snap, "lenient")
        # TransferSyntaxUID should be restored
        assert ds.file_meta.TransferSyntaxUID == original_ts
        # SOPClassUID should remain corrupted (lenient doesn't protect it)
        assert ds.SOPClassUID == "CORRUPTED"
        assert restored == 1

    def test_strict_protects_all_tiers(self):
        ds = _make_dataset()
        snap = snapshot_critical_tags(ds, "strict")
        # Corrupt everything
        ds.file_meta.TransferSyntaxUID = "1.2.3.4.5.6.7"
        ds.file_meta.MediaStorageSOPClassUID = "BAD"
        ds.file_meta.MediaStorageSOPInstanceUID = "BAD"
        ds.SOPClassUID = "BAD"
        ds.SOPInstanceUID = "BAD"
        ds.StudyInstanceUID = "BAD"
        ds.SeriesInstanceUID = "BAD"
        restored = restore_critical_tags(ds, snap, "strict")
        assert restored == 7

    def test_noop_when_nothing_changed(self):
        ds = _make_dataset()
        snap = snapshot_critical_tags(ds, "strict")
        # Mutate only a non-critical tag
        ds.PatientName = "MUTATED"
        restored = restore_critical_tags(ds, snap, "strict")
        assert restored == 0

    def test_empty_snapshot_returns_zero(self):
        ds = _make_dataset()
        restored = restore_critical_tags(ds, {}, "strict")
        assert restored == 0
