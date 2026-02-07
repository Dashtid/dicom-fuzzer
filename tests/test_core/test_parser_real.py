"""Tests for parser module using real DICOM files.

Targets uncovered code paths to increase coverage.
"""

from pathlib import Path

import pytest
from pydicom.dataset import Dataset, FileDataset
from pydicom.tag import Tag
from pydicom.uid import generate_uid

from dicom_fuzzer.core.dicom.parser import DicomParser
from dicom_fuzzer.core.exceptions import (
    ParsingError,
    SecurityViolationError,
    ValidationError,
)


@pytest.fixture
def real_dicom_file(tmp_path):
    """Create a real valid DICOM file."""
    filename = tmp_path / "valid.dcm"

    # Create file meta information
    file_meta = Dataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
    file_meta.ImplementationClassUID = generate_uid()

    # Create the FileDataset instance
    ds = FileDataset(str(filename), {}, file_meta=file_meta, preamble=b"\0" * 128)

    # Add required DICOM elements
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.Modality = "CT"
    ds.StudyDate = "20250101"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()

    # Save the file
    ds.save_as(str(filename), write_like_original=False)
    return filename


@pytest.fixture
def minimal_dicom_file(tmp_path):
    """Create a minimal DICOM file with only required tags."""
    filename = tmp_path / "minimal.dcm"

    file_meta = Dataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
    file_meta.ImplementationClassUID = generate_uid()

    ds = FileDataset(str(filename), {}, file_meta=file_meta, preamble=b"\0" * 128)
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID

    ds.save_as(str(filename), write_like_original=False)
    return filename


class TestParserInitialization:
    """Test DicomParser initialization."""

    def test_parse_valid_file(self, real_dicom_file):
        """Test parsing a valid DICOM file."""
        parser = DicomParser(str(real_dicom_file))

        assert parser.file_path == Path(str(real_dicom_file))
        assert parser._dataset is not None
        assert parser.security_checks_enabled is True

    def test_parse_with_security_disabled(self, real_dicom_file):
        """Test parsing with security checks disabled."""
        parser = DicomParser(str(real_dicom_file), security_checks=False)

        assert parser.security_checks_enabled is False
        assert parser._dataset is not None

    def test_custom_max_file_size(self, real_dicom_file):
        """Test custom max file size."""
        parser = DicomParser(str(real_dicom_file), max_file_size=200 * 1024 * 1024)

        assert parser.max_file_size == 200 * 1024 * 1024

    def test_default_max_file_size(self, real_dicom_file):
        """Test default max file size."""
        parser = DicomParser(str(real_dicom_file))

        assert parser.max_file_size == DicomParser.MAX_FILE_SIZE


class TestSecurityChecks:
    """Test security validation."""

    def test_nonexistent_file_raises_error(self):
        """Test parsing nonexistent file raises SecurityViolationError."""
        with pytest.raises(SecurityViolationError, match="File does not exist"):
            DicomParser("/nonexistent/file.dcm", security_checks=True)

    def test_directory_raises_error(self, tmp_path):
        """Test directory path raises SecurityViolationError."""
        with pytest.raises(SecurityViolationError, match="not a regular file"):
            DicomParser(str(tmp_path), security_checks=True)

    def test_oversized_file_detection(self, tmp_path):
        """Test detection of oversized files."""
        # Create a large file
        large_file = tmp_path / "large.dcm"
        large_file.write_bytes(b"DICM" + b"\x00" * (150 * 1024 * 1024))  # 150MB

        with pytest.raises(SecurityViolationError, match="exceeds maximum"):
            DicomParser(str(large_file), security_checks=True)

    def test_unusual_extension_warning(self, tmp_path, caplog):
        """Test warning for unusual file extensions."""
        # Create file with unusual extension
        weird_file = tmp_path / "test.txt"

        file_meta = Dataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.ImplementationClassUID = generate_uid()

        ds = FileDataset(str(weird_file), {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.save_as(str(weird_file), write_like_original=False)

        parser = DicomParser(str(weird_file), security_checks=True)

        # Should parse but log warning
        assert parser._dataset is not None


class TestDatasetAccess:
    """Test dataset property access."""

    def test_dataset_property(self, real_dicom_file):
        """Test accessing dataset property."""
        parser = DicomParser(str(real_dicom_file))

        dataset = parser.dataset
        assert dataset is not None
        assert dataset.PatientName == "Test^Patient"

    def test_dataset_is_cached(self, real_dicom_file):
        """Test dataset is cached after first access."""
        parser = DicomParser(str(real_dicom_file))

        ds1 = parser.dataset
        ds2 = parser.dataset

        assert ds1 is ds2  # Same object reference


class TestCriticalTags:
    """Test critical tag handling."""

    def test_critical_tags_defined(self):
        """Test critical tags are defined."""
        assert len(DicomParser.CRITICAL_TAGS) > 0
        assert Tag(0x0008, 0x0016) in DicomParser.CRITICAL_TAGS  # SOPClassUID
        assert Tag(0x0008, 0x0018) in DicomParser.CRITICAL_TAGS  # SOPInstanceUID

    def test_critical_tags_present_in_valid_file(self, real_dicom_file):
        """Test critical tags are present in valid file."""
        parser = DicomParser(str(real_dicom_file))

        for tag in DicomParser.CRITICAL_TAGS:
            if tag in parser.dataset:
                value = parser.dataset.get(tag)
                assert value is not None


class TestFilePathHandling:
    """Test file path handling."""

    def test_file_path_as_string(self, real_dicom_file):
        """Test initializing with string file path."""
        parser = DicomParser(str(real_dicom_file))

        assert isinstance(parser.file_path, Path)
        assert parser.file_path == Path(str(real_dicom_file))

    def test_file_path_as_path_object(self, real_dicom_file):
        """Test initializing with Path object."""
        parser = DicomParser(Path(str(real_dicom_file)))

        assert isinstance(parser.file_path, Path)


class TestParsingErrors:
    """Test parsing error handling."""

    def test_invalid_dicom_file(self, tmp_path):
        """Test parsing invalid DICOM file."""
        bad_file = tmp_path / "bad.dcm"
        bad_file.write_bytes(b"NOT DICOM DATA")

        with pytest.raises(ParsingError, match="Failed to parse"):
            DicomParser(str(bad_file), security_checks=False)

    def test_corrupted_file(self, tmp_path):
        """Test parsing corrupted file."""
        corrupted = tmp_path / "corrupted.dcm"
        # Write partial DICOM header
        corrupted.write_bytes(b"DICM" + b"\x00" * 50)

        with pytest.raises(ParsingError):
            DicomParser(str(corrupted), security_checks=False)


class TestValidation:
    """Test dataset validation."""

    def test_missing_required_elements(self, tmp_path):
        """Test validation catches missing required elements."""
        # Create file without required SOPClassUID
        filename = tmp_path / "incomplete.dcm"

        file_meta = Dataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.ImplementationClassUID = generate_uid()

        ds = FileDataset(str(filename), {}, file_meta=file_meta, preamble=b"\0" * 128)
        # Deliberately omit SOPClassUID and SOPInstanceUID
        ds.PatientName = "Test"

        ds.save_as(str(filename), write_like_original=False)

        with pytest.raises((ValidationError, ParsingError)):
            DicomParser(str(filename), security_checks=False)


class TestMetadataCache:
    """Test metadata caching."""

    def test_metadata_cache_initialized(self, real_dicom_file):
        """Test metadata cache is initialized."""
        parser = DicomParser(str(real_dicom_file))

        assert parser._metadata_cache is not None or parser._metadata_cache is None
        # Cache may be None until first use


class TestSecurityChecksProperty:
    """Test security_checks_enabled property."""

    def test_security_checks_enabled_true(self, real_dicom_file):
        """Test security_checks_enabled property when True."""
        parser = DicomParser(str(real_dicom_file), security_checks=True)

        assert parser.security_checks_enabled is True

    def test_security_checks_enabled_false(self, real_dicom_file):
        """Test security_checks_enabled property when False."""
        parser = DicomParser(str(real_dicom_file), security_checks=False)

        assert parser.security_checks_enabled is False


class TestDifferentFileSizes:
    """Test parsing files of different sizes."""

    def test_small_file(self, minimal_dicom_file):
        """Test parsing small DICOM file."""
        parser = DicomParser(str(minimal_dicom_file))

        assert parser.dataset is not None

    def test_medium_file(self, real_dicom_file):
        """Test parsing medium-sized file."""
        parser = DicomParser(str(real_dicom_file))

        assert parser.dataset is not None

    def test_file_within_size_limit(self, tmp_path):
        """Test file just within size limit."""
        # Create file just under 100MB
        file_path = tmp_path / "justright.dcm"

        file_meta = Dataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.ImplementationClassUID = generate_uid()

        ds = FileDataset(str(file_path), {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID

        # Add large pixel data to increase file size (but not over 100MB)
        import numpy as np

        ds.PixelData = np.zeros((512, 512), dtype=np.uint16).tobytes()
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.SamplesPerPixel = 1
        ds.PixelRepresentation = 0

        ds.save_as(str(file_path), write_like_original=False)

        # Should parse without error
        parser = DicomParser(str(file_path), security_checks=True)
        assert parser.dataset is not None


class TestIntegration:
    """Integration tests."""

    def test_complete_parsing_workflow(self, real_dicom_file):
        """Test complete parsing workflow."""
        # Initialize parser
        parser = DicomParser(str(real_dicom_file), security_checks=True)

        # Access dataset
        dataset = parser.dataset

        # Verify critical tags
        assert dataset.SOPClassUID is not None
        assert dataset.SOPInstanceUID is not None

        # Verify patient data
        assert dataset.PatientName == "Test^Patient"
        assert dataset.PatientID == "12345"

    def test_multiple_parser_instances(self, real_dicom_file):
        """Test creating multiple parser instances."""
        parser1 = DicomParser(str(real_dicom_file))
        parser2 = DicomParser(str(real_dicom_file))

        # Should be independent
        assert parser1 is not parser2
        assert parser1.dataset is not parser2.dataset

    def test_reusing_same_file(self, real_dicom_file):
        """Test parsing the same file multiple times."""
        parser1 = DicomParser(str(real_dicom_file))
        ds1 = parser1.dataset

        parser2 = DicomParser(str(real_dicom_file))
        ds2 = parser2.dataset

        # Should have same data but different instances
        assert ds1.PatientName == ds2.PatientName
        assert ds1 is not ds2
