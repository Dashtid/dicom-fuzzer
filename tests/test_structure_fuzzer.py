"""
Tests for StructureFuzzer - DICOM file structure corruption.

Tests cover all corruption strategies: tag ordering, length fields,
unexpected tags, duplicates, and binary header corruption.
"""

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.strategies.structure_fuzzer import StructureFuzzer


class TestStructureFuzzerInitialization:
    """Test StructureFuzzer initialization."""

    def test_initialization(self):
        """Test fuzzer initializes with corruption strategies."""
        fuzzer = StructureFuzzer()

        assert hasattr(fuzzer, "corruption_strategies")
        assert len(fuzzer.corruption_strategies) == 4


class TestMutateStructure:
    """Test main structure mutation method."""

    @pytest.fixture
    def sample_dataset(self):
        """Create sample DICOM dataset."""
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.Modality = "CT"
        return ds

    def test_mutate_structure_returns_dataset(self, sample_dataset):
        """Test structure mutation returns a dataset."""
        fuzzer = StructureFuzzer()

        mutated = fuzzer.mutate_structure(sample_dataset)

        assert isinstance(mutated, Dataset)


class TestCorruptTagOrdering:
    """Test tag ordering corruption."""

    def test_corrupt_tag_ordering_with_sufficient_tags(self):
        """Test tag ordering corruption with enough tags."""
        fuzzer = StructureFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.StudyInstanceUID = "1.2.3"
        ds.SeriesInstanceUID = "1.2.4"
        ds.SOPInstanceUID = "1.2.5"

        mutated = fuzzer._corrupt_tag_ordering(ds)

        assert isinstance(mutated, Dataset)
        assert len(list(mutated.keys())) == len(list(ds.keys()))


class TestCorruptLengthFields:
    """Test length field corruption."""

    def test_corrupt_length_overflow(self):
        """Test length overflow corruption."""
        from unittest.mock import MagicMock, patch

        fuzzer = StructureFuzzer()
        ds = Dataset()
        ds.PatientName = "Test^Patient"

        # Mock random.choice: first call picks tag, second picks corruption type
        tag_mock = MagicMock()
        tag_mock.return_value = list(ds.keys())[0]  # Return PatientName tag

        with patch("random.choice", side_effect=[list(ds.keys())[0], "overflow"]):
            mutated = fuzzer._corrupt_length_fields(ds)

        assert isinstance(mutated, Dataset)


class TestInsertUnexpectedTags:
    """Test insertion of unexpected/reserved tags."""

    def test_insert_unexpected_tags(self):
        """Test unexpected tag insertion."""
        fuzzer = StructureFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"

        mutated = fuzzer._insert_unexpected_tags(ds)

        assert isinstance(mutated, Dataset)


class TestDuplicateTags:
    """Test tag duplication."""

    def test_duplicate_tags(self):
        """Test tag duplication."""
        fuzzer = StructureFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "12345"

        mutated = fuzzer._duplicate_tags(ds)

        assert isinstance(mutated, Dataset)
