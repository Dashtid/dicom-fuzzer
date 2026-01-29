"""
Tests for StructureFuzzer - DICOM file structure corruption.

Tests cover all corruption strategies: tag ordering, length fields,
unexpected tags, duplicates, and binary header corruption.
"""

from pathlib import Path

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.strategies.robustness.structure_fuzzer import StructureFuzzer


class TestStructureFuzzerInitialization:
    """Test StructureFuzzer initialization."""

    def test_initialization(self):
        """Test fuzzer initializes with corruption strategies."""
        fuzzer = StructureFuzzer()

        assert fuzzer is not None
        assert hasattr(fuzzer, "corruption_strategies")
        assert isinstance(fuzzer.corruption_strategies, list)
        assert len(fuzzer.corruption_strategies) == 6


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

        assert mutated is not None
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

        assert mutated is not None
        assert isinstance(mutated, Dataset)
        assert len(list(mutated.keys())) == len(list(ds.keys()))
        assert len(list(mutated.keys())) == 5


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

        assert mutated is not None
        assert isinstance(mutated, Dataset)


class TestInsertUnexpectedTags:
    """Test insertion of unexpected/reserved tags."""

    def test_insert_unexpected_tags(self):
        """Test unexpected tag insertion."""
        fuzzer = StructureFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"

        mutated = fuzzer._insert_unexpected_tags(ds)

        assert mutated is not None
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

        assert mutated is not None
        assert isinstance(mutated, Dataset)

    def test_duplicate_tags_empty_dataset(self):
        """Test tag duplication with empty dataset."""
        fuzzer = StructureFuzzer()
        ds = Dataset()

        mutated = fuzzer._duplicate_tags(ds)

        assert mutated is not None
        assert isinstance(mutated, Dataset)


class TestCorruptFileHeader:
    """Test binary file header corruption."""

    def test_corrupt_file_header_preamble(self, tmp_path):
        """Test corrupting file preamble."""
        from unittest.mock import patch

        fuzzer = StructureFuzzer()

        # Create test DICOM file
        test_file = tmp_path / "test.dcm"
        # Create minimal valid DICOM file structure
        file_data = bytearray(200)
        file_data[128:132] = b"DICM"  # DICOM prefix
        test_file.write_bytes(file_data)

        with patch("random.choice", return_value="corrupt_preamble"):
            output = fuzzer.corrupt_file_header(str(test_file))

        assert output is not None
        assert isinstance(output, str)
        assert Path(output).exists()

    def test_corrupt_file_header_dicm_prefix(self, tmp_path):
        """Test corrupting DICM prefix."""
        from unittest.mock import patch

        fuzzer = StructureFuzzer()

        test_file = tmp_path / "test.dcm"
        file_data = bytearray(200)
        file_data[128:132] = b"DICM"
        test_file.write_bytes(file_data)

        with patch("random.choice", return_value="corrupt_dicm_prefix"):
            output = fuzzer.corrupt_file_header(str(test_file))

        assert output is not None
        # Verify DICM was corrupted
        with open(output, "rb") as f:
            data = f.read()
            assert data[128:132] == b"XXXX"

    def test_corrupt_file_header_transfer_syntax(self, tmp_path):
        """Test corrupting transfer syntax."""
        from unittest.mock import patch

        fuzzer = StructureFuzzer()

        test_file = tmp_path / "test.dcm"
        file_data = bytearray(300)
        file_data[128:132] = b"DICM"
        test_file.write_bytes(file_data)

        with patch("random.choice", return_value="corrupt_transfer_syntax"):
            output = fuzzer.corrupt_file_header(str(test_file))

        assert output is not None
        assert isinstance(output, str)
        assert Path(output).exists()

    def test_corrupt_file_header_truncate(self, tmp_path):
        """Test file truncation."""
        from unittest.mock import patch

        fuzzer = StructureFuzzer()

        test_file = tmp_path / "test.dcm"
        file_data = bytearray(2000)
        file_data[128:132] = b"DICM"
        test_file.write_bytes(file_data)

        with patch("random.choice", return_value="truncate_file"):
            output = fuzzer.corrupt_file_header(str(test_file))

        assert output is not None
        # Verify file was truncated
        assert Path(output).stat().st_size < 2000

    def test_corrupt_file_header_custom_output(self, tmp_path):
        """Test corruption with custom output path."""
        from unittest.mock import patch

        fuzzer = StructureFuzzer()

        test_file = tmp_path / "test.dcm"
        output_file = tmp_path / "custom_output.dcm"
        file_data = bytearray(200)
        file_data[128:132] = b"DICM"
        test_file.write_bytes(file_data)

        with patch("random.choice", return_value="corrupt_preamble"):
            output = fuzzer.corrupt_file_header(str(test_file), str(output_file))

        assert output == str(output_file)
        assert output_file.exists()

    def test_corrupt_file_header_nonexistent_file(self, tmp_path):
        """Test corruption of nonexistent file."""
        fuzzer = StructureFuzzer()

        output = fuzzer.corrupt_file_header(str(tmp_path / "nonexistent.dcm"))

        assert output is None


class TestAdditionalCoverage:
    """Additional tests for edge cases and missing coverage."""

    def test_corrupt_tag_ordering_few_tags(self):
        """Test tag ordering with too few tags."""
        fuzzer = StructureFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"

        mutated = fuzzer._corrupt_tag_ordering(ds)

        assert mutated is not None
        assert isinstance(mutated, Dataset)

    def test_corrupt_tag_ordering_with_file_meta(self):
        """Test tag ordering preserves file_meta."""
        from pydicom.dataset import FileMetaDataset

        fuzzer = StructureFuzzer()
        ds = Dataset()
        ds.file_meta = FileMetaDataset()
        ds.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        ds.PatientName = "Test1"
        ds.PatientID = "Test2"
        ds.StudyInstanceUID = "Test3"

        mutated = fuzzer._corrupt_tag_ordering(ds)

        assert hasattr(mutated, "file_meta")

    def test_corrupt_length_underflow(self):
        """Test length underflow corruption."""
        from unittest.mock import patch

        fuzzer = StructureFuzzer()
        ds = Dataset()
        ds.PatientName = "TestPatient"

        with patch("random.choice", side_effect=[list(ds.keys())[0], "underflow"]):
            mutated = fuzzer._corrupt_length_fields(ds)

        assert mutated.PatientName == ""

    def test_corrupt_length_mismatch(self):
        """Test length mismatch corruption with null bytes."""
        from unittest.mock import patch

        fuzzer = StructureFuzzer()
        ds = Dataset()
        ds.PatientName = "LongTestPatientName"

        with patch("random.choice", side_effect=[list(ds.keys())[0], "mismatch"]):
            mutated = fuzzer._corrupt_length_fields(ds)

        assert "\x00" in str(mutated.PatientName)

    def test_corrupt_length_no_string_tags(self):
        """Test length corruption with no string tags."""
        fuzzer = StructureFuzzer()
        ds = Dataset()
        # Add only non-string element
        ds.add_new(0x00280010, "US", 512)  # Rows - unsigned short

        mutated = fuzzer._corrupt_length_fields(ds)

        assert mutated is not None
        assert isinstance(mutated, Dataset)


class TestIntegrationScenarios:
    """Integration tests for complete fuzzing workflows."""

    def test_multiple_mutations_sequential(self):
        """Test applying multiple mutations sequentially."""
        fuzzer = StructureFuzzer()
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = "1.2.3.4"
        ds.Modality = "CT"

        # Apply mutations multiple times
        for _ in range(3):
            ds = fuzzer.mutate_structure(ds)

        assert ds is not None
        assert isinstance(ds, Dataset)

    def test_all_corruption_strategies(self):
        """Test all corruption strategies individually."""
        fuzzer = StructureFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.StudyInstanceUID = "1.2.3"

        # Test each strategy
        mutated1 = fuzzer._corrupt_tag_ordering(ds)
        mutated2 = fuzzer._corrupt_length_fields(ds)
        mutated3 = fuzzer._insert_unexpected_tags(ds)
        mutated4 = fuzzer._duplicate_tags(ds)

        assert all(
            isinstance(m, Dataset) for m in [mutated1, mutated2, mutated3, mutated4]
        )
