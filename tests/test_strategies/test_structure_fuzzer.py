"""Tests for structure_fuzzer.py - DICOM Structure Attacks.

Tests cover structure mutations, tag corruption, and file header manipulation.
"""

import random
from pathlib import Path
from unittest.mock import patch

from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.strategies.structure_fuzzer import StructureFuzzer


class TestStructureFuzzerInit:
    """Test StructureFuzzer initialization."""

    def test_init_corruption_strategies(self):
        """Test that fuzzer initializes with corruption strategies."""
        fuzzer = StructureFuzzer()
        assert len(fuzzer.corruption_strategies) == 4
        assert callable(fuzzer.corruption_strategies[0])

    def test_init_strategies_are_methods(self):
        """Test that all strategies are callable methods."""
        fuzzer = StructureFuzzer()
        for strategy in fuzzer.corruption_strategies:
            assert hasattr(strategy, "__call__")


class TestMutateStructure:
    """Test mutate_structure method."""

    def test_mutate_structure_returns_dataset(self):
        """Test that mutate_structure returns a dataset."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"
        dataset.PatientName = "Test^Patient"

        result = fuzzer.mutate_structure(dataset)
        assert isinstance(result, Dataset)

    def test_mutate_structure_applies_strategies(self):
        """Test that mutate_structure applies corruption strategies."""
        fuzzer = StructureFuzzer()

        # Track which strategies were called
        call_count = [0]
        original_strategies = fuzzer.corruption_strategies.copy()

        def mock_strategy(ds):
            call_count[0] += 1
            return ds

        fuzzer.corruption_strategies = [mock_strategy] * 4

        dataset = Dataset()
        dataset.PatientID = "12345"

        with patch.object(random, "randint", return_value=2):
            with patch.object(
                random, "sample", return_value=[mock_strategy, mock_strategy]
            ):
                fuzzer.mutate_structure(dataset)

        assert call_count[0] == 2


class TestCorruptTagOrdering:
    """Test _corrupt_tag_ordering method."""

    def test_corrupt_tag_ordering_with_elements(self):
        """Test tag ordering corruption with multiple elements."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"
        dataset.PatientName = "Test^Patient"
        dataset.StudyDate = "20230101"
        dataset.Modality = "CT"

        # Force a specific swap
        with patch.object(random, "sample", return_value=[0, 2]):
            result = fuzzer._corrupt_tag_ordering(dataset)

        assert isinstance(result, Dataset)

    def test_corrupt_tag_ordering_few_elements(self):
        """Test tag ordering with insufficient elements."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"
        # Only 1 element - too few to swap

        result = fuzzer._corrupt_tag_ordering(dataset)
        assert result == dataset

    def test_corrupt_tag_ordering_preserves_file_meta(self):
        """Test that file_meta is preserved during corruption."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"
        dataset.PatientName = "Test^Patient"
        dataset.StudyDate = "20230101"
        dataset.Modality = "CT"

        # Add file_meta
        file_meta = Dataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        dataset.file_meta = file_meta

        with patch.object(random, "sample", return_value=[0, 2]):
            result = fuzzer._corrupt_tag_ordering(dataset)

        assert hasattr(result, "file_meta")
        assert result.file_meta.TransferSyntaxUID == "1.2.840.10008.1.2"


class TestCorruptLengthFields:
    """Test _corrupt_length_fields method."""

    def test_corrupt_length_overflow(self):
        """Test length overflow corruption."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        with patch.object(random, "choice") as mock_choice:
            mock_choice.side_effect = [
                Tag("PatientName"),  # Choose PatientName tag
                "overflow",  # Choose overflow corruption
            ]
            result = fuzzer._corrupt_length_fields(dataset)

        # Value should have been extended
        assert isinstance(result, Dataset)

    def test_corrupt_length_underflow(self):
        """Test length underflow corruption."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        with patch.object(random, "choice") as mock_choice:
            mock_choice.side_effect = [
                Tag("PatientName"),
                "underflow",
            ]
            result = fuzzer._corrupt_length_fields(dataset)

        assert isinstance(result, Dataset)

    def test_corrupt_length_mismatch(self):
        """Test length mismatch corruption."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        with patch.object(random, "choice") as mock_choice:
            mock_choice.side_effect = [
                Tag("PatientName"),
                "mismatch",
            ]
            result = fuzzer._corrupt_length_fields(dataset)

        assert isinstance(result, Dataset)

    def test_corrupt_length_no_string_tags(self):
        """Test corruption when no string tags exist."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        # Only add a non-string type element
        dataset.Rows = 512
        dataset.Columns = 512

        result = fuzzer._corrupt_length_fields(dataset)
        assert result == dataset


class TestInsertUnexpectedTags:
    """Test _insert_unexpected_tags method."""

    def test_insert_unexpected_tags(self):
        """Test inserting unexpected tags."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"

        with patch.object(random, "randint", return_value=1):
            with patch.object(random, "choice", return_value=0xDEADBEEF):
                result = fuzzer._insert_unexpected_tags(dataset)

        assert isinstance(result, Dataset)

    def test_insert_unexpected_tags_handles_failure(self):
        """Test that failures during tag insertion are handled."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"

        # Mock add_new to always fail
        with patch.object(dataset, "add_new", side_effect=Exception("Cannot add tag")):
            with patch.object(random, "randint", return_value=1):
                with patch.object(random, "choice", return_value=0xFFFFFFFF):
                    # Should not raise, just log and continue
                    result = fuzzer._insert_unexpected_tags(dataset)

        assert isinstance(result, Dataset)


class TestDuplicateTags:
    """Test _duplicate_tags method."""

    def test_duplicate_tags(self):
        """Test tag duplication."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        with patch.object(random, "choice", return_value=Tag("PatientName")):
            result = fuzzer._duplicate_tags(dataset)

        assert isinstance(result, Dataset)

    def test_duplicate_tags_empty_dataset(self):
        """Test duplication on empty dataset."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()

        result = fuzzer._duplicate_tags(dataset)
        assert result == dataset

    def test_duplicate_tags_handles_failure(self):
        """Test that failures during duplication are handled."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        # Mock add_new to fail
        with patch.object(
            dataset, "add_new", side_effect=Exception("Duplicate not allowed")
        ):
            with patch.object(random, "choice", return_value=Tag("PatientName")):
                result = fuzzer._duplicate_tags(dataset)

        assert isinstance(result, Dataset)


class TestCorruptFileHeader:
    """Test corrupt_file_header method."""

    def test_corrupt_file_header_preamble(self, tmp_path):
        """Test preamble corruption."""
        fuzzer = StructureFuzzer()

        # Create a minimal DICOM-like file
        test_file = tmp_path / "test.dcm"
        file_data = b"\x00" * 128 + b"DICM" + b"\x00" * 100
        test_file.write_bytes(file_data)

        with patch.object(random, "choice", return_value="corrupt_preamble"):
            result = fuzzer.corrupt_file_header(str(test_file))

        assert result is not None
        assert Path(result).exists()

    def test_corrupt_file_header_dicm_prefix(self, tmp_path):
        """Test DICM prefix corruption."""
        fuzzer = StructureFuzzer()

        test_file = tmp_path / "test.dcm"
        file_data = b"\x00" * 128 + b"DICM" + b"\x00" * 100
        test_file.write_bytes(file_data)

        output_file = tmp_path / "output.dcm"

        with patch.object(random, "choice", return_value="corrupt_dicm_prefix"):
            result = fuzzer.corrupt_file_header(str(test_file), str(output_file))

        assert result == str(output_file)
        corrupted_data = output_file.read_bytes()
        assert corrupted_data[128:132] == b"XXXX"

    def test_corrupt_file_header_transfer_syntax(self, tmp_path):
        """Test transfer syntax corruption."""
        fuzzer = StructureFuzzer()

        test_file = tmp_path / "test.dcm"
        file_data = b"\x00" * 128 + b"DICM" + b"\x00" * 100
        test_file.write_bytes(file_data)

        with patch.object(random, "choice", return_value="corrupt_transfer_syntax"):
            result = fuzzer.corrupt_file_header(str(test_file))

        assert result is not None

    def test_corrupt_file_header_truncate(self, tmp_path):
        """Test file truncation."""
        fuzzer = StructureFuzzer()

        test_file = tmp_path / "test.dcm"
        file_data = b"\x00" * 128 + b"DICM" + b"\x00" * 2000
        test_file.write_bytes(file_data)

        with patch.object(random, "choice", return_value="truncate_file"):
            with patch.object(random, "randint", return_value=1000):
                result = fuzzer.corrupt_file_header(str(test_file))

        assert result is not None
        corrupted_data = Path(result).read_bytes()
        assert len(corrupted_data) == 1000

    def test_corrupt_file_header_failure(self, tmp_path):
        """Test handling of file operation failure."""
        fuzzer = StructureFuzzer()

        # Non-existent file
        result = fuzzer.corrupt_file_header(str(tmp_path / "nonexistent.dcm"))
        assert result is None

    def test_corrupt_file_header_auto_output_path(self, tmp_path):
        """Test auto-generated output path."""
        fuzzer = StructureFuzzer()

        test_file = tmp_path / "test.dcm"
        file_data = b"\x00" * 128 + b"DICM" + b"\x00" * 100
        test_file.write_bytes(file_data)

        with patch.object(random, "choice", return_value="corrupt_preamble"):
            result = fuzzer.corrupt_file_header(str(test_file))

        assert result is not None
        assert "_header_corrupted" in result
