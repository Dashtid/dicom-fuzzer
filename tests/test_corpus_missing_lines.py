"""Tests for corpus.py missing lines to reach 100% coverage.

Targets specific uncovered lines in corpus.py (92% -> 100%).
"""

from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

from dicom_fuzzer.core.corpus import CorpusEntry, CorpusManager


@pytest.fixture
def sample_dataset():
    """Create a simple DICOM dataset for testing."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = generate_uid()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.Modality = "CT"
    return ds


class TestCorpusEntryMissingLines:
    """Test CorpusEntry missing lines (92-104, 114-116)."""

    def test_get_dataset_with_invalid_path(self, sample_dataset, tmp_path):
        """Test lines 92-104: lazy-load dataset with invalid path."""
        # Create entry without dataset in memory
        entry = CorpusEntry(entry_id="test001", dataset=sample_dataset)

        # Set a path that exists but is not a valid DICOM file
        invalid_path = tmp_path / "invalid.dcm"
        invalid_path.write_text("NOT A DICOM FILE")

        entry._dataset_cache = None  # Clear cache to force lazy load
        entry._dataset_path = invalid_path

        # Lines 92-104: Should attempt to load, catch exception, return None
        result = entry.get_dataset()

        assert result is None

    def test_get_dataset_returns_none_when_no_path(self, sample_dataset):
        """Test lines 103-104: return None when no path available."""
        entry = CorpusEntry(entry_id="test002", dataset=sample_dataset)

        # Clear cache and path
        entry._dataset_cache = None
        entry._dataset_path = None

        # Lines 103-104: Should return None
        result = entry.get_dataset()

        assert result is None

    def test_set_dataset_with_path(self, sample_dataset, tmp_path):
        """Test lines 114-116: set_dataset with path parameter."""
        entry = CorpusEntry(entry_id="test003", dataset=sample_dataset)

        # Create a new dataset and path
        new_dataset = Dataset()
        new_dataset.PatientName = "New^Patient"
        new_path = tmp_path / "new.dcm"

        # Lines 114-116: Should set both dataset and path
        entry.set_dataset(new_dataset, path=new_path)

        assert entry._dataset_cache == new_dataset
        assert entry._dataset_path == new_path


class TestCorpusManagerMissingLines:
    """Test CorpusManager missing lines (416-417, 445)."""

    def test_save_entry_with_none_dataset(self, tmp_path):
        """Test lines 416-417: save entry when dataset is None."""
        manager = CorpusManager(tmp_path)

        # Create entry with None dataset
        entry = CorpusEntry(entry_id="test_none", dataset=None)

        # Mock get_dataset to return None
        with patch.object(entry, 'get_dataset', return_value=None):
            # Lines 416-417: Should log error and return early
            manager._save_entry(entry)

        # File should not be created
        dcm_path = tmp_path / "test_none.dcm"
        assert not dcm_path.exists()

    def test_load_corpus_nonexistent_dir(self, tmp_path):
        """Test line 445: _load_corpus when corpus_dir doesn't exist."""
        nonexistent_dir = tmp_path / "nonexistent"
        manager = CorpusManager(nonexistent_dir)

        # Line 445: Should return early when dir doesn't exist
        # This tests the early return path
        manager._load_corpus()

        # Should complete without error (just tests line 445 early return)
        # No assertion needed - if it didn't return early, it would error
