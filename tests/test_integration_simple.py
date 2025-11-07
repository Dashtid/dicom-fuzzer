"""Simple Integration Tests for DICOM Fuzzer

These tests verify basic integration between key modules without requiring
all complex dependencies.
"""

import tempfile
from pathlib import Path

import pytest
from pydicom import Dataset
from pydicom.uid import generate_uid

# Import only the core classes we need that are exported
from dicom_fuzzer.core import (
    DICOMGenerator,
    DicomMutator,
    DicomParser,
    DicomSeries,
    DicomValidator,
    SeriesDetector,
    SeriesValidator,
)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_dicom_file(temp_dir):
    """Create a sample DICOM file for testing."""
    ds = Dataset()
    ds.PatientName = "TEST^PATIENT"
    ds.PatientID = "12345"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = generate_uid()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    ds.Modality = "CT"
    ds.Rows = 128
    ds.Columns = 128
    ds.BitsAllocated = 16
    ds.PixelData = b"\x00" * (128 * 128 * 2)

    file_path = temp_dir / "sample.dcm"
    ds.save_as(str(file_path), implicit_vr=True, little_endian=True)
    return file_path


@pytest.fixture
def sample_dicom_series(temp_dir):
    """Create a sample DICOM series with multiple slices."""
    series_uid = generate_uid()
    study_uid = generate_uid()

    files = []
    for i in range(3):
        ds = Dataset()
        ds.PatientName = "SERIES^TEST"
        ds.PatientID = "54321"
        ds.StudyInstanceUID = study_uid
        ds.SeriesInstanceUID = series_uid
        ds.SOPInstanceUID = generate_uid()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.4"  # MR Image Storage
        ds.InstanceNumber = i + 1
        ds.Modality = "MR"
        ds.Rows = 256
        ds.Columns = 256
        ds.BitsAllocated = 16
        ds.PixelData = b"\x00" * (256 * 256 * 2)

        file_path = temp_dir / f"slice_{i:03d}.dcm"
        ds.save_as(str(file_path), implicit_vr=True, little_endian=True)
        files.append(file_path)

    return files


class TestBasicIntegration:
    """Test basic integration between core modules."""

    def test_parse_validate_mutate_workflow(self, sample_dicom_file):
        """Test the basic workflow of parsing, validating, and mutating a DICOM file."""
        # Parse the file
        parser = DicomParser(str(sample_dicom_file))
        metadata = parser.parse()
        assert metadata is not None
        assert "PatientName" in metadata
        assert metadata["PatientName"] == "TEST^PATIENT"

        # Validate the file
        validator = DicomValidator()
        is_valid = validator.validate(str(sample_dicom_file))
        assert is_valid

        # Mutate the file
        mutator = DicomMutator()
        mutated_ds = mutator.mutate(str(sample_dicom_file))
        assert mutated_ds is not None
        # The mutated dataset should be different in some way
        assert hasattr(mutated_ds, "PatientName")

    def test_generator_creates_valid_dicom(self, temp_dir):
        """Test that DICOMGenerator creates valid DICOM files."""
        generator = DICOMGenerator()

        # Generate a basic DICOM
        output_path = temp_dir / "generated.dcm"
        generator.generate(str(output_path))

        assert output_path.exists()

        # Parse the generated file
        parser = DicomParser(str(output_path))
        metadata = parser.parse()
        assert metadata is not None

        # Validate the generated file
        validator = DicomValidator()
        is_valid = validator.validate(str(output_path))
        assert is_valid

    def test_series_detection_and_validation(self, sample_dicom_series, temp_dir):
        """Test detection and validation of a DICOM series."""
        # Detect series
        detector = SeriesDetector()
        series_map = detector.detect_series(str(temp_dir))

        # Should detect one series
        assert len(series_map) == 1
        series_uid = list(series_map.keys())[0]
        series_files = series_map[series_uid]
        assert len(series_files) == 3

        # Create DicomSeries object
        series = DicomSeries(
            series_uid=series_uid, files=[str(f) for f in sample_dicom_series]
        )
        assert series.slice_count == 3

        # Validate the series
        validator = SeriesValidator()
        validation_result = validator.validate(series)
        assert validation_result.is_valid
        assert len(validation_result.issues) == 0

    def test_parser_handles_invalid_file(self, temp_dir):
        """Test that parser handles invalid files gracefully."""
        invalid_file = temp_dir / "invalid.dcm"
        invalid_file.write_bytes(b"NOT_A_DICOM_FILE")

        parser = DicomParser(str(invalid_file))
        with pytest.raises(Exception):
            parser.parse()

    def test_validator_detects_invalid_file(self, temp_dir):
        """Test that validator detects invalid files."""
        invalid_file = temp_dir / "invalid.dcm"
        invalid_file.write_bytes(b"NOT_A_DICOM_FILE")

        validator = DicomValidator()
        is_valid = validator.validate(str(invalid_file))
        assert not is_valid

    def test_mutator_preserves_required_tags(self, sample_dicom_file):
        """Test that mutator preserves required DICOM tags."""
        mutator = DicomMutator()
        mutated_ds = mutator.mutate(str(sample_dicom_file))

        # Check that essential tags are preserved
        assert hasattr(mutated_ds, "StudyInstanceUID")
        assert hasattr(mutated_ds, "SeriesInstanceUID")
        assert hasattr(mutated_ds, "SOPInstanceUID")
        assert hasattr(mutated_ds, "Modality")

    def test_generator_with_custom_tags(self, temp_dir):
        """Test generator with custom tags."""
        generator = DICOMGenerator()

        output_path = temp_dir / "custom.dcm"
        tags = {
            "PatientName": "CUSTOM^NAME",
            "PatientID": "CUSTOM123",
            "Modality": "US",
        }
        generator.generate(str(output_path), tags=tags)

        # Parse and verify custom tags
        parser = DicomParser(str(output_path))
        metadata = parser.parse()
        assert metadata["PatientName"] == "CUSTOM^NAME"
        assert metadata["PatientID"] == "CUSTOM123"
        assert metadata["Modality"] == "US"


class TestErrorHandling:
    """Test error handling in integration scenarios."""

    def test_parser_with_corrupted_header(self, temp_dir):
        """Test parser with corrupted DICOM header."""
        corrupted = temp_dir / "corrupted.dcm"
        # Start with DICM but corrupt the rest
        corrupted.write_bytes(b"DICM" + b"\xff" * 100)

        parser = DicomParser(str(corrupted))
        with pytest.raises(Exception):
            parser.parse()

    def test_mutator_with_empty_file(self, temp_dir):
        """Test mutator with empty file."""
        empty_file = temp_dir / "empty.dcm"
        empty_file.write_bytes(b"")

        mutator = DicomMutator()
        with pytest.raises(Exception):
            mutator.mutate(str(empty_file))

    def test_series_detector_with_mixed_files(self, temp_dir):
        """Test series detector with mixed DICOM and non-DICOM files."""
        # Create a valid DICOM
        ds = Dataset()
        ds.SeriesInstanceUID = generate_uid()
        ds.SOPInstanceUID = generate_uid()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
        valid_file = temp_dir / "valid.dcm"
        ds.save_as(str(valid_file), implicit_vr=True, little_endian=True)

        # Create a non-DICOM file
        invalid_file = temp_dir / "invalid.txt"
        invalid_file.write_text("Not a DICOM")

        # Detector should handle mixed files
        detector = SeriesDetector()
        series_map = detector.detect_series(str(temp_dir))

        # Should detect only the valid DICOM
        assert len(series_map) == 1
